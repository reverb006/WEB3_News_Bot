"""
Archive Module — Dual Knowledge Base for Web3 Security & Ecosystem Intelligence.

Maintains two comprehensive, human-readable markdown knowledge bases:
1. reports/archive_security.md:
   - Web3 exploits, hacks, vulnerabilities, post-mortems, and security research.
   - Includes severity, protocol, loss amounts, attack vectors, chains, summaries, and links.
2. reports/archive_news.md:
   - Major Web3 ecosystem milestones, protocol launches, EIPs, and regulations.
   - Includes category, key takeaways, source, and links.

Features:
- Incremental appending on new classifications
- Full backfill & synchronization from SQLite database
- Zero duplicate entries
- Clean markdown formatting
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from app.database.db import Database
from app.models.schemas import Classification

logger = logging.getLogger(__name__)

# Root directory resolution
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
REPORTS_DIR = ROOT_DIR / "reports"
SECURITY_ARCHIVE_PATH = REPORTS_DIR / "archive_security.md"
NEWS_ARCHIVE_PATH = REPORTS_DIR / "archive_news.md"

SECURITY_CATEGORIES = {
    "CRITICAL_SECURITY",
    "HIGH_SECURITY",
    "SECURITY_RESEARCH",
    "DEFI_EXPLOIT",
    "SMART_CONTRACT_VULN",
    "PHISHING_SCAM",
    "INFRASTRUCTURE_HACK",
    "VULNERABILITY",
}


def is_security_item(article: dict) -> bool:
    """Determine if an article belongs in the Security Archive vs News Archive."""
    cat = (article.get("category") or "").upper()
    if cat in SECURITY_CATEGORIES:
        return True
    if (article.get("security_relevance") or 0) >= 60:
        return True
    if (article.get("estimated_loss_usd") or 0) > 0:
        return True
    if article.get("protocol") and cat not in ("MAJOR_WEB3_NEWS", "PROTOCOL_UPDATE", "REGULATION"):
        return True
    return False


def _clean_str(val: Optional[str], default: str = "") -> str:
    return (val or default).strip()


def _format_date(date_str: Optional[str]) -> str:
    if not date_str:
        return "Unknown Date"
    try:
        clean = date_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return date_str[:10]


def format_security_entry(item: dict) -> str:
    """Format a single security incident/exploit for archive_security.md."""
    title = _clean_str(item.get("title"), "Untitled Incident")
    url = _clean_str(item.get("url"), "#")
    date = _format_date(item.get("published_at") or item.get("first_seen_at"))
    severity = (item.get("severity") or "HIGH").upper()
    protocol = item.get("protocol") or "Ecosystem"
    loss = item.get("estimated_loss_usd")
    loss_txt = f"${loss:,.2f}" if loss and loss > 0 else "Undisclosed / N/A"
    priority = item.get("priority_score") or 0
    source = _clean_str(item.get("source_name"), "Security Feed")
    summary = _clean_str(item.get("summary"), "No technical summary recorded.")

    # Attack types
    attack_raw = item.get("attack_type")
    attacks = []
    if isinstance(attack_raw, str):
        try:
            attacks = json.loads(attack_raw)
        except Exception:
            attacks = [attack_raw]
    elif isinstance(attack_raw, list):
        attacks = attack_raw
    attacks_str = ", ".join(str(a) for a in attacks if a and a != "UNKNOWN") or "Unspecified"

    # Chains
    chain_raw = item.get("chain")
    chains = []
    if isinstance(chain_raw, str):
        try:
            chains = json.loads(chain_raw)
        except Exception:
            chains = [chain_raw]
    elif isinstance(chain_raw, list):
        chains = chain_raw
    chains_str = ", ".join(str(c) for c in chains if c) or "Multi-chain / Unknown"

    # Severity badge
    if severity == "CRITICAL":
        sev_badge = "🚨 CRITICAL"
    elif severity == "HIGH":
        sev_badge = "⚠️ HIGH"
    elif "RESEARCH" in (item.get("category") or ""):
        sev_badge = "🔬 RESEARCH"
    else:
        sev_badge = "🛡️ MEDIUM/LOW"

    lines = [
        f"### {title}",
        f"- **Date:** `{date}` | **Severity:** `{sev_badge}` | **Priority:** `{priority}/100`",
        f"- **Target Protocol:** `{protocol}` | **Estimated Loss:** **{loss_txt}**",
        f"- **Attack Vector:** `{attacks_str}` | **Chain:** `{chains_str}`",
        f"- **Source:** {source} | [Reference Link]({url})",
        f"- **Executive Summary:** {summary}",
        "",
        "---",
        "",
    ]
    return "\n".join(lines)


def format_news_entry(item: dict) -> str:
    """Format a single major news item for archive_news.md."""
    title = _clean_str(item.get("title"), "Untitled News")
    url = _clean_str(item.get("url"), "#")
    date = _format_date(item.get("published_at") or item.get("first_seen_at"))
    category = item.get("category") or "MAJOR_WEB3_NEWS"
    priority = item.get("priority_score") or 0
    source = _clean_str(item.get("source_name"), "Web3 News")
    summary = _clean_str(item.get("summary"), "No summary recorded.")

    # Category badge
    if category == "MAJOR_WEB3_NEWS":
        cat_badge = "🌐 MAJOR NEWS"
    elif category == "PROTOCOL_UPDATE":
        cat_badge = "⚡ PROTOCOL UPDATE"
    elif category == "REGULATION":
        cat_badge = "🏛️ REGULATION"
    else:
        cat_badge = f"📰 {category}"

    lines = [
        f"### {title}",
        f"- **Date:** `{date}` | **Category:** `{cat_badge}` | **Priority:** `{priority}/100`",
        f"- **Source:** {source} | [Original Article]({url})",
        f"- **Key Takeaways:** {summary}",
        "",
        "---",
        "",
    ]
    return "\n".join(lines)


class ArchiveManager:
    """
    Manages reading, writing, and incremental updates to the dual knowledge archives.
    """

    def __init__(self, reports_dir: Optional[Path] = None):
        self.reports_dir = reports_dir or REPORTS_DIR
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.security_path = self.reports_dir / "archive_security.md"
        self.news_path = self.reports_dir / "archive_news.md"

    def archive_article(self, article: dict, classification: Optional[Classification] = None) -> bool:
        """
        Append a single article to the appropriate archive file if not already present.
        """
        try:
            url = article.get("url") or ""
            target_path = self.security_path if is_security_item(article) else self.news_path

            # If file doesn't exist yet, initialize it
            if not target_path.exists():
                self._init_archive_file(target_path)

            content = target_path.read_text(encoding="utf-8")
            # Deduplicate by URL or exact title
            title = article.get("title") or ""
            if (url and url in content) or (title and f"### {title}" in content):
                logger.debug(f"Article '{title[:30]}' already archived in {target_path.name}")
                return False

            # Format entry
            if is_security_item(article):
                entry_text = format_security_entry(article)
            else:
                entry_text = format_news_entry(article)

            # Append to file
            with open(target_path, "a", encoding="utf-8") as f:
                f.write(entry_text)

            logger.info(f"Archived '{title[:40]}' to {target_path.name}")
            return True
        except Exception as e:
            logger.error(f"Failed to archive article: {e}", exc_info=True)
            return False

    def _init_archive_file(self, path: Path) -> None:
        """Create empty archive with header banner."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        if path == self.security_path:
            header = [
                "# 🛡️ Web3 Security Intelligence Archive",
                "",
                f"> Canonical repository of Web3 security exploits, vulnerability disclosures, post-mortems, and audits.",
                f"> **Last Updated:** `{now}`",
                "",
                "---",
                "",
            ]
        else:
            header = [
                "# 🌐 Major Web3 Ecosystem & News Archive",
                "",
                f"> Canonical repository of major Web3 ecosystem milestones, protocol updates, EIPs, and regulations.",
                f"> **Last Updated:** `{now}`",
                "",
                "---",
                "",
            ]
        path.write_text("\n".join(header), encoding="utf-8")

    async def backfill_archives(self, db: Database) -> dict:
        """
        Sync & backfill both archives from all classified articles in the database.
        Completely rebuilds both files cleanly sorted by date descending.
        """
        logger.info("Starting complete archive backfill from SQLite database...")
        cursor = await db.conn.execute(
            """
            SELECT a.*, s.name as source_name
            FROM articles a
            JOIN sources s ON a.source_id = s.id
            WHERE a.classified_at IS NOT NULL
              AND a.category NOT IN ('IGNORE', 'LOW_VALUE')
            ORDER BY COALESCE(a.published_at, a.first_seen_at) DESC
            """
        )
        columns = [desc[0] for desc in cursor.description]
        rows = await cursor.fetchall()
        all_articles = [dict(zip(columns, row)) for row in rows]

        security_items = []
        news_items = []

        seen_urls = set()
        for art in all_articles:
            url = art.get("url")
            if url in seen_urls:
                continue
            seen_urls.add(url)

            if is_security_item(art):
                security_items.append(art)
            else:
                news_items.append(art)

        # Build Security Archive
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        total_loss = sum(item.get("estimated_loss_usd") or 0.0 for item in security_items)

        sec_lines = [
            "# 🛡️ Web3 Security Intelligence Archive",
            "",
            "> Canonical repository of Web3 security exploits, vulnerability disclosures, post-mortems, and audits.",
            f"> **Total Incidents Recorded:** `{len(security_items)}` | **Tracked Cumulative Losses:** `${total_loss:,.2f}`",
            f"> **Last Updated:** `{now_str}`",
            "",
            "---",
            "",
        ]
        for sec in security_items:
            sec_lines.append(format_security_entry(sec))

        self.security_path.write_text("\n".join(sec_lines), encoding="utf-8")
        logger.info(f"Wrote {len(security_items)} security entries to {self.security_path}")

        # Build News Archive
        news_lines = [
            "# 🌐 Major Web3 Ecosystem & News Archive",
            "",
            "> Canonical repository of major Web3 ecosystem milestones, protocol updates, EIPs, and regulations.",
            f"> **Total Articles Recorded:** `{len(news_items)}`",
            f"> **Last Updated:** `{now_str}`",
            "",
            "---",
            "",
        ]
        for news in news_items:
            news_lines.append(format_news_entry(news))

        self.news_path.write_text("\n".join(news_lines), encoding="utf-8")
        logger.info(f"Wrote {len(news_items)} news entries to {self.news_path}")

        return {
            "security_count": len(security_items),
            "news_count": len(news_items),
            "total": len(security_items) + len(news_items),
            "security_file": str(self.security_path),
            "news_file": str(self.news_path),
        }
