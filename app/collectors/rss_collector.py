"""
RSS Collector — fetches and parses RSS/Atom feeds.

How it works:
  1. Downloads the feed XML using httpx (with timeout + retries)
  2. Parses it with feedparser (handles RSS 2.0, Atom, malformed XML)
  3. Cleans HTML from titles and descriptions
  4. Converts each entry into a RawArticle

Error handling:
  - Network errors → logged, returns empty list
  - Malformed XML → feedparser handles gracefully, skips bad entries
  - Missing fields → uses defaults, never crashes
  - Each entry is processed independently (one bad entry doesn't skip others)

Retry strategy:
  - 3 attempts with exponential backoff (1s, 2s, 4s)
  - Only retries on network/server errors, not on 404
"""

from __future__ import annotations

import asyncio
import html
import logging
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Optional

import feedparser
import httpx

from app.collectors.base import BaseCollector
from app.models.schemas import RawArticle, SourceConfig

logger = logging.getLogger(__name__)

# Regex to strip HTML tags from feed content
HTML_TAG_RE = re.compile(r"<[^>]+>")

# Max content length to store (keeps DB size reasonable)
MAX_CONTENT_LENGTH = 5000

# HTTP request settings
REQUEST_TIMEOUT = 30  # seconds
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 1  # seconds (1, 2, 4)


def _strip_html(text: str) -> str:
    """
    Remove HTML tags and decode HTML entities from text.

    feedparser often returns HTML in descriptions. We want plain text
    for Gemini classification (HTML wastes tokens and confuses the model).
    """
    if not text:
        return ""
    # Remove HTML tags
    cleaned = HTML_TAG_RE.sub(" ", text)
    # Decode HTML entities (&amp; → &, etc.)
    cleaned = html.unescape(cleaned)
    # Collapse whitespace
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def _parse_date(entry: dict) -> Optional[datetime]:
    """
    Extract publication date from a feed entry.

    feedparser provides `published_parsed` (a time.struct_time) for most feeds.
    Falls back to `updated_parsed`. Returns None if no date is available.
    """
    # feedparser's pre-parsed date
    for field in ("published_parsed", "updated_parsed"):
        parsed = entry.get(field)
        if parsed:
            try:
                # struct_time → datetime (feedparser gives UTC)
                from calendar import timegm
                timestamp = timegm(parsed)
                return datetime.fromtimestamp(timestamp, tz=timezone.utc)
            except (ValueError, OverflowError, OSError):
                continue

    # Fallback: try parsing the raw string
    for field in ("published", "updated"):
        raw = entry.get(field, "")
        if raw:
            try:
                return parsedate_to_datetime(raw)
            except (ValueError, TypeError):
                continue

    return None


def _get_entry_url(entry: dict) -> str:
    """Extract the canonical URL from a feed entry."""
    # Prefer `link`, fall back to `id`
    return entry.get("link", "") or entry.get("id", "")


def _get_entry_content(entry: dict) -> str:
    """
    Extract the best available text content from a feed entry.

    Feeds put content in different places:
      - entry.content[0].value (full Atom content)
      - entry.summary (RSS description)
      - entry.description (alias for summary)
    """
    # Try full content first (Atom feeds)
    content_list = entry.get("content", [])
    if content_list and isinstance(content_list, list):
        raw = content_list[0].get("value", "")
        if raw:
            return _strip_html(raw)[:MAX_CONTENT_LENGTH]

    # Fall back to summary/description
    summary = entry.get("summary", "") or entry.get("description", "")
    return _strip_html(summary)[:MAX_CONTENT_LENGTH]


class RSSCollector(BaseCollector):
    """
    Collector for RSS and Atom feeds.

    Fetches the feed, parses entries, and returns RawArticle objects.
    Handles network errors, malformed feeds, and missing data gracefully.
    """

    async def collect(self) -> list[RawArticle]:
        """
        Fetch the RSS feed and convert entries to RawArticle objects.

        Returns empty list on any error (network, parsing, etc.).
        """
        self.logger.info(f"Collecting from {self.source.name} ({self.source.url})")

        # Step 1: Download the feed XML
        feed_text = await self._fetch_feed()
        if not feed_text:
            return []

        # Step 2: Parse with feedparser
        feed = feedparser.parse(feed_text)

        if feed.bozo and not feed.entries:
            # bozo=True means feedparser found errors. If there are still
            # entries, we use them anyway (many feeds have minor issues).
            self.logger.warning(
                f"Feed {self.source.name} is malformed and has no entries: "
                f"{feed.bozo_exception}"
            )
            return []

        # Step 3: Convert entries to RawArticle objects
        articles: list[RawArticle] = []
        for entry in feed.entries[: self.source.max_items]:
            try:
                article = self._parse_entry(entry)
                if article:
                    articles.append(article)
            except Exception as e:
                # One bad entry should never stop us from processing others
                self.logger.warning(
                    f"Failed to parse entry in {self.source.name}: {e}"
                )
                continue

        self.logger.info(
            f"Collected {len(articles)} articles from {self.source.name}"
        )
        return articles

    async def _fetch_feed(self) -> Optional[str]:
        """
        Download the RSS feed XML with retries and exponential backoff.

        Returns the raw XML text, or None on failure.
        """
        last_error: Optional[Exception] = None

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                async with httpx.AsyncClient(
                    timeout=REQUEST_TIMEOUT,
                    follow_redirects=True,
                    # Set a reasonable User-Agent so feeds don't block us
                    headers={
                        "User-Agent": "Web3SecurityRadar/0.1 (Personal Security Monitor)"
                    },
                ) as client:
                    response = await client.get(self.source.url)

                    if response.status_code == 200:
                        return response.text

                    # Don't retry client errors (404, 403, etc.)
                    if 400 <= response.status_code < 500:
                        self.logger.error(
                            f"Feed {self.source.name} returned {response.status_code} "
                            f"(not retrying client errors)"
                        )
                        return None

                    # Server errors (5xx) → retry
                    self.logger.warning(
                        f"Feed {self.source.name} returned {response.status_code} "
                        f"(attempt {attempt}/{MAX_RETRIES})"
                    )
                    last_error = Exception(f"HTTP {response.status_code}")

            except (httpx.TimeoutException, httpx.NetworkError, httpx.HTTPError) as e:
                last_error = e
                self.logger.warning(
                    f"Network error fetching {self.source.name}: {e} "
                    f"(attempt {attempt}/{MAX_RETRIES})"
                )

            # Exponential backoff before retry
            if attempt < MAX_RETRIES:
                wait_time = RETRY_BACKOFF_BASE * (2 ** (attempt - 1))
                await asyncio.sleep(wait_time)

        self.logger.error(
            f"Failed to fetch {self.source.name} after {MAX_RETRIES} attempts: "
            f"{last_error}"
        )
        return None

    def _parse_entry(self, entry: dict) -> Optional[RawArticle]:
        """
        Convert a single feedparser entry dict into a RawArticle.

        Returns None if the entry is missing required fields (URL or title).
        """
        url = _get_entry_url(entry)
        if not url:
            self.logger.debug("Skipping entry with no URL")
            return None

        title = _strip_html(entry.get("title", ""))
        if not title:
            self.logger.debug(f"Skipping entry with no title: {url}")
            return None

        content = _get_entry_content(entry)
        published = _parse_date(entry)

        return RawArticle(
            url=url,
            title=title,
            content=content,
            published_at=published,
            source_name=self.source.name,
            source_type=self.source.source_type,
            source_reliability=self.source.reliability_score,
        )
