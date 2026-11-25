"""
Deduplication & Incident Merging Engine — merges multi-source reports into unified incidents.

How it works:
1. Normalizes article titles (strips filler words, punctuation, stopwords).
2. Computes fuzzy similarity using both sequence matching and token Jaccard overlap.
3. Incorporates protocol entity matching:
   - If both articles identify the same protocol within 72 hours, the matching threshold is lowered.
4. Manages Incident lifecycle:
   - First report creates a canonical Incident record in SQLite.
   - Subsequent reports link to the existing Incident and reference the original article.
   - Increments article corroboration count (1 source -> 2 sources -> 3 sources).
5. Suppresses duplicate Telegram alerts:
   - If an alert has already fired for an incident, duplicate reports do NOT send duplicate pings.
"""

from __future__ import annotations

import difflib
import json
import logging
import re
from datetime import datetime, timezone
from typing import Optional, Tuple

from app.database.db import Database
from app.models.schemas import Classification

logger = logging.getLogger(__name__)

# Common prefixes and noise in Web3 security headlines
PREFIX_PATTERNS = [
    r"^\[.*?\]\s*",                 # [PeckShieldAlert], [Immunefi]
    r"^(breaking|update|alert|report|analysis|post-mortem|postmortem)\s*:\s*",
    r"^security\s+alert\s*:\s*",
    r"^web3\s+security\s*:\s*",
]

# Stopwords to filter out during tokenization
STOPWORDS = {
    "a", "an", "the", "and", "or", "in", "on", "at", "to", "for", "of",
    "with", "by", "from", "up", "about", "into", "over", "after", "is",
    "are", "was", "were", "be", "been", "being", "have", "has", "had",
    "do", "does", "did", "how", "what", "why", "when", "where", "who",
    "will", "would", "could", "should", "may", "might", "must", "can",
    "via", "over", "due",
}

# Similarity thresholds
DEFAULT_TITLE_SIMILARITY_THRESHOLD = 0.65
SAME_PROTOCOL_SIMILARITY_THRESHOLD = 0.30
INCIDENT_LOOKBACK_HOURS = 72


def normalize_title(title: str) -> str:
    """
    Clean and normalize a title string for fuzzy comparison.
    Strips noise prefixes, punctuation, and multiple spaces.
    """
    if not title:
        return ""

    text = title.strip()

    # Remove common prefix tags like "[PeckShield] ", "BREAKING: "
    for pattern in PREFIX_PATTERNS:
        text = re.sub(pattern, "", text, flags=re.IGNORECASE)

    # Lowercase and remove punctuation except alphanumeric and spaces
    text = text.lower()
    text = re.sub(r"[^\w\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()

    return text


def tokenize(text: str) -> set[str]:
    """Extract significant keywords from normalized text."""
    words = text.split()
    return {w for w in words if w not in STOPWORDS and len(w) > 2}


def compute_title_similarity(title1: str, title2: str) -> float:
    """
    Compute similarity score (0.0 to 1.0) between two titles.
    Uses maximum of sequence similarity and token Jaccard similarity.
    """
    norm1 = normalize_title(title1)
    norm2 = normalize_title(title2)

    if not norm1 or not norm2:
        return 0.0

    if norm1 == norm2:
        return 1.0

    tokens1 = tokenize(norm1)
    tokens2 = tokenize(norm2)

    # If both have significant tokens, require at least one common keyword
    if tokens1 and tokens2:
        intersection = len(tokens1 & tokens2)
        if intersection == 0:
            return 0.0

        jaccard = intersection / len(tokens1 | tokens2)
        overlap = intersection / min(len(tokens1), len(tokens2))
        seq_ratio = difflib.SequenceMatcher(None, norm1, norm2).ratio()
        return max(jaccard, overlap * 0.7, seq_ratio)

    # Fallback to SequenceMatcher if no significant tokens extracted
    return difflib.SequenceMatcher(None, norm1, norm2).ratio()


def are_articles_related(
    title1: str,
    title2: str,
    protocol1: Optional[str] = None,
    protocol2: Optional[str] = None,
) -> bool:
    """
    Determine if two articles refer to the exact same security event.
    """
    sim = compute_title_similarity(title1, title2)

    # If both specify the exact same protocol, lower threshold applies
    if protocol1 and protocol2:
        p1 = protocol1.strip().lower()
        p2 = protocol2.strip().lower()
        if p1 == p2 and p1 not in ("", "unknown"):
            # Lower threshold when protocols match
            return sim >= SAME_PROTOCOL_SIMILARITY_THRESHOLD

    # Otherwise require standard strong similarity
    return sim >= DEFAULT_TITLE_SIMILARITY_THRESHOLD


class IncidentManager:
    """
    Coordinates deduplication, incident creation, article linking, and alert suppression.
    """

    def __init__(self, lookback_hours: int = INCIDENT_LOOKBACK_HOURS):
        self.lookback_hours = lookback_hours

    async def find_matching_incident(
        self,
        db: Database,
        title: str,
        protocol: Optional[str] = None,
    ) -> Optional[dict]:
        """
        Check if an incoming article matches an existing incident from the last N hours.

        Args:
            db: Database instance.
            title: Title of the incoming article.
            protocol: Protocol extracted by AI (if any).

        Returns:
            Matching incident dictionary, or None if new incident.
        """
        active_incidents = await db.get_active_incidents(hours=self.lookback_hours)

        for incident in active_incidents:
            inc_title = incident.get("title") or ""
            inc_proto = incident.get("protocol")

            if are_articles_related(title, inc_title, protocol, inc_proto):
                logger.info(
                    f"Match found: '{title[:45]}' -> Incident #{incident['id']} '{inc_title[:45]}'"
                )
                return incident

            # Also check against individual articles already linked to this incident
            linked_articles = await db.get_incident_articles(incident["id"])
            for linked in linked_articles:
                l_title = linked.get("title") or ""
                l_proto = linked.get("protocol")
                if are_articles_related(title, l_title, protocol, l_proto):
                    logger.info(
                        f"Match found via linked article: '{title[:45]}' -> Incident #{incident['id']}"
                    )
                    return incident

        return None

    async def process_and_link(
        self,
        db: Database,
        article_id: int,
        title: str,
        classification: Classification,
    ) -> Tuple[int, bool]:
        """
        Process a classified article: link to an existing incident or create a new one.

        Args:
            db: Database instance.
            article_id: ID of the article in the database.
            title: Article title.
            classification: Structured AI classification.

        Returns:
            Tuple of (incident_id, is_new_incident).
        """
        protocol = classification.protocol
        loss = classification.estimated_loss_usd
        severity = classification.severity.value
        chains = classification.chain
        attack_types = [at.value for at in classification.attack_type]

        # 1. Search for matching active incident
        existing_incident = await self.find_matching_incident(db, title, protocol)

        if existing_incident:
            incident_id = existing_incident["id"]

            # Find the primary article ID for this incident
            linked_articles = await db.get_incident_articles(incident_id)
            primary_id = linked_articles[0]["id"] if linked_articles else None

            # Update incident stats (increments article_count, updates loss if higher)
            await db.update_incident(
                incident_id=incident_id,
                estimated_loss_usd=loss,
                severity=severity,
            )

            # Link article to incident and set duplicate pointer
            await db.link_article_to_incident(
                article_id=article_id,
                incident_id=incident_id,
                duplicate_of=primary_id,
            )

            logger.info(
                f"Merged article {article_id} into Incident #{incident_id} "
                f"(total sources: {existing_incident.get('article_count', 1) + 1})"
            )
            return incident_id, False

        else:
            # 2. Create brand new incident
            incident_id = await db.create_incident(
                title=classification.title or title,
                protocol=protocol,
                chain=chains,
                attack_type=attack_types,
                estimated_loss_usd=loss,
                severity=severity,
                status="active",
            )

            # Link this primary article to the new incident
            await db.link_article_to_incident(
                article_id=article_id,
                incident_id=incident_id,
                duplicate_of=None,
            )

            logger.info(f"Created new Incident #{incident_id} for article {article_id}")
            return incident_id, True

    @staticmethod
    def is_article_fresh(published_at: Optional[str], max_age_hours: int = 400) -> bool:
        """
        Check if an article was published within max_age_hours from now.
        Returns False if the article is older than max_age_hours (e.g. historical 2021-2023 hacks).
        Returns True if fresh, or if published_at is None/cannot be parsed.
        """
        if not published_at:
            return True

        try:
            clean = published_at.strip().replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            age_seconds = (now - dt).total_seconds()
            if age_seconds < 0:
                return True
            return age_seconds <= (max_age_hours * 3600)
        except Exception:
            try:
                from email.utils import parsedate_to_datetime
                dt = parsedate_to_datetime(published_at)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                age_seconds = (now - dt).total_seconds()
                if age_seconds < 0:
                    return True
                return age_seconds <= (max_age_hours * 3600)
            except Exception:
                return True

    async def should_dispatch_alert(
        self,
        db: Database,
        incident_id: int,
        priority_score: int,
        should_alert: bool,
        published_at: Optional[str] = None,
        max_age_hours: int = 400,
    ) -> bool:
        """
        Determine if an alert should be sent to Telegram.
        Suppresses alert if:
        1. Published timestamp is older than max_age_hours (default 48h) - prevents historical alert storms.
        2. Priority does not meet threshold (priority < 70 and not should_alert).
        3. An alert was ALREADY sent for this incident.
        """
        # Freshness filter: do not buzz user for historical articles/exploits
        if published_at and not self.is_article_fresh(published_at, max_age_hours=max_age_hours):
            logger.info(
                f"Suppressing real-time alert for Incident #{incident_id}: "
                f"article is older than {max_age_hours}h (published_at={published_at})"
            )
            return False

        # Must meet priority threshold
        if priority_score < 70 and not should_alert:
            return False

        # Check if already alerted for this incident
        already_alerted = await db.has_incident_been_alerted(incident_id)
        if already_alerted:
            logger.info(
                f"Suppressing duplicate alert for Incident #{incident_id} (already alerted)"
            )
            return False

        return True


# Convenient module-level alias
is_article_fresh = IncidentManager.is_article_fresh
