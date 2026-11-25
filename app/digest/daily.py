"""
Daily Security Digest Generator — compiles 24h Web3 security intelligence.

Features:
- Aggregates classified articles and corroborated incidents for any date (or latest active date)
- Computes total financial losses and incident metrics
- Groups findings into auditor-focused intelligence categories:
  1. Critical Exploits & Losses
  2. Bug Bounty Disclosures & Post-Mortems
  3. Security Research & Audit Methodology
  4. Protocol Upgrades, EIPs & Governance
  5. Top 5 Must-Read Items (by priority score)
- Generates publication-grade Markdown reports saved to `reports/digest_YYYY-MM-DD.md`
- Formats Telegram HTML digest cards with multi-part chunking (respecting 4096 char limits)
- Tracks digest dispatches in SQLite to prevent duplicate deliveries
"""

from __future__ import annotations

import html
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.config.settings import get_settings, PROJECT_ROOT
from app.database.db import Database
from app.models.schemas import DailyDigest

logger = logging.getLogger(__name__)

REPORTS_DIR = PROJECT_ROOT / "reports"
TELEGRAM_MAX_MESSAGE_LEN = 3900


class DailyDigestGenerator:
    """
    Compiles, formats, and dispatches the daily Web3 security intelligence digest.
    """

    async def compile_digest(
        self,
        db: Database,
        target_date: Optional[str] = None,
    ) -> DailyDigest:
        """
        Query database and compile raw articles/incidents into structured DailyDigest data.
        """
        # Resolve date
        if not target_date or target_date.lower() == "latest":
            latest = await db.get_latest_classified_date()
            target_date = latest or datetime.now(timezone.utc).strftime("%Y-%m-%d")

        articles = await db.get_articles_for_digest(target_date)
        incidents = await db.get_incidents_for_digest(target_date)

        # Calculate loss total
        total_loss = 0.0
        seen_incident_ids = set()
        for inc in incidents:
            loss = inc.get("estimated_loss_usd")
            if loss and loss > 0:
                total_loss += loss
            seen_incident_ids.add(inc.get("id"))

        # Also check articles that might have losses not linked to incidents
        for art in articles:
            if art.get("incident_id") not in seen_incident_ids:
                loss = art.get("estimated_loss_usd")
                if loss and loss > 0:
                    total_loss += loss

        # Categorize articles
        critical_exploits: list[dict] = []
        bug_bounties: list[dict] = []
        security_research: list[dict] = []
        protocol_updates: list[dict] = []

        seen_article_ids = set()

        for art in articles:
            aid = art["id"]
            cat = art.get("category") or "UNKNOWN"
            src_name = (art.get("source_name") or "").lower()
            title = (art.get("title") or "").lower()
            prio = art.get("priority_score") or 0
            loss = art.get("estimated_loss_usd") or 0.0

            # 1. Critical Exploits & Losses
            if (
                cat in ("CRITICAL_SECURITY", "HIGH_SECURITY")
                or loss > 0
                or prio >= 75
            ):
                critical_exploits.append(art)
                seen_article_ids.add(aid)
                continue

            # 2. Bug Bounties
            if (
                cat == "BUG_BOUNTY"
                or "immunefi" in src_name
                or any(kw in title for kw in ("bug bounty", "bounty program", "bugfix review", "payout"))
            ):
                bug_bounties.append(art)
                seen_article_ids.add(aid)
                continue

            # 3. Security Research
            if (
                cat == "SECURITY_RESEARCH"
                or any(kw in src_name for kw in ("trail of bits", "peckshield", "chainalysis"))
            ):
                security_research.append(art)
                seen_article_ids.add(aid)
                continue

            # 4. Protocol Updates & EIPs
            if (
                cat == "PROTOCOL_UPDATE"
                or any(kw in src_name for kw in ("ethereum foundation", "chainlink"))
                or any(kw in title for kw in ("eip-", "erc-", "upgrade", "hard fork", "client release"))
            ):
                protocol_updates.append(art)
                seen_article_ids.add(aid)
                continue

            # Default to security research if high priority, else ignore from main sections
            if prio >= 40:
                security_research.append(art)

        # Top 5 must-read items across all articles
        sorted_articles = sorted(articles, key=lambda x: x.get("priority_score") or 0, reverse=True)
        top_must_read = sorted_articles[:5]

        return DailyDigest(
            digest_date=target_date,
            total_articles=len(articles),
            total_incidents=len(incidents),
            total_loss_usd=total_loss,
            critical_exploits=critical_exploits,
            bug_bounties=bug_bounties,
            security_research=security_research,
            protocol_updates=protocol_updates,
            top_must_read=top_must_read,
        )

    def generate_markdown_digest(self, digest: DailyDigest) -> str:
        """
        Generate a publication-grade Markdown daily security intelligence brief.
        """
        loss_str = f"${digest.total_loss_usd:,.2f}" if digest.total_loss_usd > 0 else "$0 (No Confirmed Losses)"

        lines = [
            f"# 🛡️ Web3 Security Radar — Daily Intelligence Digest",
            f"**Date:** `{digest.digest_date}`  ",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            "",
            "---",
            "",
            "## 📊 Executive Snapshot",
            "",
            "| Metric | Value |",
            "|:---|:---|",
            f"| **Classified Articles Reviewed** | `{digest.total_articles}` |",
            f"| **Unique Security Incidents** | `{digest.total_incidents}` |",
            f"| **Total Confirmed Loss** | `{loss_str}` |",
            f"| **Critical Exploits & Alerts** | `{len(digest.critical_exploits)}` |",
            f"| **Bug Bounty & Disclosures** | `{len(digest.bug_bounties)}` |",
            f"| **Research & Audit Papers** | `{len(digest.security_research)}` |",
            f"| **Protocol & Core Upgrades** | `{len(digest.protocol_updates)}` |",
            "",
            "---",
            "",
            "## 🚨 1. Critical Exploits & Losses",
            "",
        ]

        if not digest.critical_exploits:
            lines.append("*(No critical exploit alerts or confirmed exploit losses recorded for this period.)*\n")
        else:
            for art in digest.critical_exploits:
                prio = art.get("priority_score", 0)
                title = art.get("title", "Untitled")
                url = art.get("url", "#")
                src = art.get("source_name", "Source")
                proto = art.get("protocol") or "Unknown Protocol"
                loss = art.get("estimated_loss_usd")
                loss_txt = f" | **Loss:** `${loss:,.0f}`" if loss else ""
                summary = art.get("summary") or "No summary available."

                lines.extend([
                    f"### [{title}]({url})",
                    f"- **Priority:** `{prio}/100` | **Source:** {src} | **Protocol:** `{proto}`{loss_txt}",
                    f"- **Summary:** {summary}",
                    "",
                ])

        lines.extend([
            "## 🐞 2. Bug Bounty Programs & Post-Mortem Disclosures",
            "",
        ])

        if not digest.bug_bounties:
            lines.append("*(No new bug bounty program announcements or bugfix reviews recorded.)*\n")
        else:
            for art in digest.bug_bounties:
                prio = art.get("priority_score", 0)
                title = art.get("title", "Untitled")
                url = art.get("url", "#")
                src = art.get("source_name", "Source")
                summary = art.get("summary") or ""

                lines.append(f"- **[{title}]({url})** (`{src}` | Prio: `{prio}`)")
                if summary:
                    lines.append(f"  > {summary}")
            lines.append("")

        lines.extend([
            "## 🔬 3. Security Research, Tooling & Audit Methodology",
            "",
        ])

        if not digest.security_research:
            lines.append("*(No security research papers recorded for this period.)*\n")
        else:
            for art in digest.security_research:
                prio = art.get("priority_score", 0)
                title = art.get("title", "Untitled")
                url = art.get("url", "#")
                src = art.get("source_name", "Source")
                summary = art.get("summary") or ""

                lines.append(f"- **[{title}]({url})** (`{src}` | Prio: `{prio}`)")
                if summary:
                    lines.append(f"  > {summary}")
            lines.append("")

        lines.extend([
            "## ⚡ 4. Protocol Updates, EIPs & Client Releases",
            "",
        ])

        if not digest.protocol_updates:
            lines.append("*(No major protocol upgrades or EIP announcements recorded for this period.)*\n")
        else:
            for art in digest.protocol_updates:
                prio = art.get("priority_score", 0)
                title = art.get("title", "Untitled")
                url = art.get("url", "#")
                src = art.get("source_name", "Source")
                summary = art.get("summary") or ""

                lines.append(f"- **[{title}]({url})** (`{src}` | Prio: `{prio}`)")
                if summary:
                    lines.append(f"  > {summary}")
            lines.append("")

        lines.extend([
            "## 🏆 5. Top 5 Must-Read Items",
            "",
        ])

        for rank, art in enumerate(digest.top_must_read, 1):
            prio = art.get("priority_score", 0)
            title = art.get("title", "Untitled")
            url = art.get("url", "#")
            src = art.get("source_name", "Source")
            cat = art.get("category", "SECURITY")

            lines.append(f"{rank}. **[{title}]({url})**")
            lines.append(f"   - **Score:** `{prio}/100` | **Category:** `{cat}` | **Source:** {src}")

        lines.extend([
            "",
            "---",
            "*Web3 Security Radar — Autonomous Auditor Intelligence Pipeline*",
            "",
        ])

        return "\n".join(lines)

    def save_digest_report(self, digest_date: str, markdown_content: str) -> Path:
        """
        Save the digest markdown document to `reports/digest_YYYY-MM-DD.md`.
        """
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        filename = f"digest_{digest_date}.md"
        file_path = REPORTS_DIR / filename
        file_path.write_text(markdown_content, encoding="utf-8")
        logger.info(f"Saved Daily Digest report to: {file_path}")
        return file_path

    def format_telegram_digest(self, digest: DailyDigest) -> list[str]:
        """
        Format clean, rich HTML Telegram digest card(s).
        Returns a list of messages (chunked if over 3900 characters).
        """
        date_str = digest.digest_date
        loss_val = digest.total_loss_usd
        loss_display = f"${loss_val:,.0f}" if loss_val > 0 else "$0"

        # Build Section 1: Header + Stats + Exploits
        p1_lines = [
            f"🛡️ <b>WEB3 SECURITY RADAR — DAILY DIGEST</b>",
            f"📅 <i>{html.escape(date_str)}</i>",
            "",
            f"📊 <b>Snapshot:</b> {digest.total_articles} articles | {digest.total_incidents} incidents | 💸 <b>Loss:</b> {loss_display}",
            "",
        ]

        if digest.critical_exploits:
            p1_lines.append("🚨 <b>CRITICAL EXPLOITS &amp; LOSSES:</b>")
            for art in digest.critical_exploits[:3]:
                title = html.escape(art.get("title", "Exploit"))
                url = art.get("url", "#")
                loss = art.get("estimated_loss_usd")
                loss_str = f" (${loss:,.0f})" if loss else ""
                proto = art.get("protocol")
                tag = f" #{html.escape(''.join(c for c in proto if c.isalnum()))}" if proto else ""
                p1_lines.append(f"• <a href=\"{url}\"><b>{title}</b></a>{tag}{loss_str}")
            p1_lines.append("")

        if digest.bug_bounties:
            p1_lines.append("🐞 <b>BUG BOUNTIES &amp; DISCLOSURES:</b>")
            for art in digest.bug_bounties[:3]:
                title = html.escape(art.get("title", "Bounty"))
                url = art.get("url", "#")
                src = html.escape(art.get("source_name", "Platform"))
                p1_lines.append(f"• <a href=\"{url}\">{title}</a> <i>({src})</i>")
            p1_lines.append("")

        # Section 2: Research & Top Picks
        p2_lines = []
        if digest.security_research:
            p2_lines.append("🔬 <b>SECURITY RESEARCH HIGHLIGHTS:</b>")
            for art in digest.security_research[:3]:
                title = html.escape(art.get("title", "Research"))
                url = art.get("url", "#")
                src = html.escape(art.get("source_name", "Firm"))
                p2_lines.append(f"• <a href=\"{url}\">{title}</a> <i>({src})</i>")
            p2_lines.append("")

        if digest.top_must_read:
            p2_lines.append("🏆 <b>TOP MUST-READ FOR AUDITORS:</b>")
            for i, art in enumerate(digest.top_must_read[:3], 1):
                title = html.escape(art.get("title", "Article"))
                url = art.get("url", "#")
                prio = art.get("priority_score", 0)
                p2_lines.append(f"{i}. <a href=\"{url}\"><b>{title}</b></a> <code>[{prio}/100]</code>")
            p2_lines.append("")

        p2_lines.append("📄 <i>Full report generated in reports/digest_" + date_str + ".md</i>")

        # Check if everything fits in 1 message
        full_text = "\n".join(p1_lines + p2_lines)
        if len(full_text) <= TELEGRAM_MAX_MESSAGE_LEN:
            return [full_text]

        # Otherwise split into 2 clean messages
        msg1 = "\n".join(p1_lines)
        msg2 = "\n".join([f"🛡️ <b>DIGEST ({html.escape(date_str)}) — PART 2</b>", ""] + p2_lines)
        return [msg1, msg2]


async def run_daily_digest(
    db: Database,
    target_date: Optional[str] = None,
    send_telegram: bool = True,
    force: bool = False,
) -> tuple[Optional[Path], list[int]]:
    """
    Generate the daily digest, persist to DB, write Markdown file, and dispatch to Telegram.

    Returns:
        tuple of (saved_markdown_path, list_of_telegram_message_ids)
    """
    generator = DailyDigestGenerator()

    # Determine date
    if not target_date or target_date.lower() == "latest":
        latest = await db.get_latest_classified_date()
        target_date = latest or datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Check if already sent
    if not force and await db.has_digest_been_sent(target_date):
        logger.info(f"Daily digest for {target_date} has already been generated and sent. Use force=True to re-generate.")
        return None, []

    # Compile data
    digest_data = await generator.compile_digest(db, target_date)
    if digest_data.total_articles == 0:
        logger.warning(f"No classified articles found for date {target_date}.")

    # Generate and save markdown report
    markdown_content = generator.generate_markdown_digest(digest_data)
    report_path = generator.save_digest_report(target_date, markdown_content)

    # Save to SQLite
    await db.save_digest(
        digest_date=target_date,
        content=markdown_content,
        article_count=digest_data.total_articles,
        incident_count=digest_data.total_incidents,
        status="sent" if send_telegram else "saved",
    )

    # Send Telegram broadcast
    telegram_msg_ids: list[int] = []
    if send_telegram:
        settings = get_settings()
        if settings.has_telegram:
            from app.alerts.telegram import TelegramAlertManager
            alert_mgr = TelegramAlertManager()
            cards = generator.format_telegram_digest(digest_data)
            for card in cards:
                mid = await alert_mgr.send_message(card)
                if mid:
                    telegram_msg_ids.append(mid)

    return report_path, telegram_msg_ids
