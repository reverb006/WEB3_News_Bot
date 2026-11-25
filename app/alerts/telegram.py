"""
Telegram Alert Dispatcher — formats and delivers real-time Web3 security alerts.

Features:
- Formats rich security alert cards using Telegram HTML (safe against unescaped markdown chars)
- Distinct visual badges for CRITICAL, HIGH, and SECURITY_RESEARCH
- Extracts protocol, estimated loss, attack vector, and chain details
- Tracks sent alerts in SQLite to prevent duplicate spam
- Handles network errors and rate limits cleanly
"""

from __future__ import annotations

import asyncio
import html
import json
import logging
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional, Union

from app.config.settings import get_settings
from app.database.db import Database
from app.models.schemas import Classification, Severity, Category

logger = logging.getLogger(__name__)


def format_alert_message(article: dict) -> str:
    """
    Format a classified article into a rich HTML Telegram alert card.

    Args:
        article: Dict containing article columns from SQLite (title, url, category,
                 severity, priority_score, protocol, attack_type, estimated_loss_usd,
                 chain, summary, source_name).

    Returns:
        Formatted HTML string ready for Telegram sendMessage.
    """
    title = html.escape(article.get("title") or "Untitled Incident")
    url = article.get("url") or ""
    category = article.get("category") or "SECURITY"
    severity = (article.get("severity") or "HIGH").upper()
    priority = article.get("priority_score") or 0
    protocol = article.get("protocol")
    source_name = html.escape(article.get("source_name") or "Unknown Source")
    summary = html.escape(article.get("summary") or "No detailed summary available.")
    loss_usd = article.get("estimated_loss_usd")

    # Attack types (may be JSON array string or list)
    attack_raw = article.get("attack_type")
    attack_types = []
    if isinstance(attack_raw, str):
        try:
            attack_types = json.loads(attack_raw)
        except Exception:
            attack_types = [attack_raw]
    elif isinstance(attack_raw, list):
        attack_types = attack_raw

    # Chains (may be JSON array string or list)
    chain_raw = article.get("chain")
    chains = []
    if isinstance(chain_raw, str):
        try:
            chains = json.loads(chain_raw)
        except Exception:
            chains = [chain_raw]
    elif isinstance(chain_raw, list):
        chains = chain_raw

    is_news = category in ("MAJOR_WEB3_NEWS", "PROTOCOL_UPDATE", "REGULATION", "GENERAL_NEWS")

    # Pick emoji and title badge
    if category == "MAJOR_WEB3_NEWS":
        badge = "🌐 <b>MAJOR WEB3 ECOSYSTEM NEWS</b>"
    elif category == "PROTOCOL_UPDATE":
        badge = "⚡ <b>PROTOCOL & INFRASTRUCTURE UPDATE</b>"
    elif category == "REGULATION":
        badge = "🏛️ <b>REGULATORY & COMPLIANCE UPDATE</b>"
    elif severity == "CRITICAL" or category == "CRITICAL_SECURITY":
        badge = "🚨 <b>CRITICAL WEB3 EXPLOIT DETECTED</b>"
    elif severity == "HIGH" or category == "HIGH_SECURITY":
        badge = "⚠️ <b>HIGH-SEVERITY SECURITY ALERT</b>"
    elif "RESEARCH" in category:
        badge = "🔬 <b>SECURITY RESEARCH & AUDIT FINDINGS</b>"
    else:
        badge = "🛡️ <b>WEB3 SECURITY INTELLIGENCE</b>"

    lines = [
        badge,
        "",
        f"<b>{title}</b>",
        "",
    ]

    # Key details block
    details = []
    if protocol:
        clean_tag = "".join(c for c in protocol if c.isalnum())
        details.append(f"🎯 <b>Protocol:</b> {html.escape(protocol)} (#{clean_tag})")

    if loss_usd and loss_usd > 0:
        details.append(f"💰 <b>Estimated Loss:</b> ${loss_usd:,.2f}")

    if attack_types and attack_types != ["UNKNOWN"]:
        attacks_str = ", ".join(html.escape(str(a)) for a in attack_types)
        details.append(f"⚡ <b>Attack Vector:</b> {attacks_str}")

    if chains:
        chains_str = ", ".join(html.escape(str(c)) for c in chains)
        details.append(f"⛓️ <b>Chain:</b> {chains_str}")

    if is_news:
        details.append(f"🏷️ <b>Category:</b> {category} | <b>Priority:</b> {priority}/100")
    else:
        details.append(f"📊 <b>Severity:</b> {severity} | <b>Priority:</b> {priority}/100")
    details.append(f"📰 <b>Source:</b> {source_name}")

    lines.extend(details)
    lines.append("")

    # AI Summary
    lines.append("📝 <b>Summary:</b>")
    lines.append(f"<i>{summary}</i>")
    lines.append("")

    # Link button / link text
    if url:
        link_label = "Read Full Coverage" if is_news else "Read Full Incident Report"
        lines.append(f'🔗 <a href="{html.escape(url)}">{link_label}</a>')

    return "\n".join(lines)


class TelegramAlertManager:
    """
    Manages dispatching formatted alerts to Telegram and recording them in SQLite.
    """

    def __init__(self, bot_token: Optional[str] = None, chat_id: Optional[str] = None):
        settings = get_settings()
        self.settings = settings
        self.bot_token = bot_token or settings.telegram_bot_token
        self.chat_id = chat_id or settings.telegram_chat_id

        if not self.bot_token or not self.chat_id:
            logger.warning("Telegram credentials not fully configured in settings.")

    @property
    def is_configured(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    async def send_message(
        self, html_text: str, reply_markup: Optional[dict] = None
    ) -> Optional[int]:
        """
        Send an HTML-formatted message to the configured Telegram chat with optional inline keyboard.

        Returns:
            Telegram message_id on success, or None on failure.
        """
        if not self.is_configured:
            logger.error("Cannot send Telegram message: credentials not configured.")
            return None

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        data_payload = {
            "chat_id": self.chat_id,
            "text": html_text,
            "parse_mode": "HTML",
            "disable_web_page_preview": False,
        }
        if reply_markup:
            data_payload["reply_markup"] = reply_markup

        payload = json.dumps(data_payload).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )

        def _do_send():
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode("utf-8"))

        try:
            res_data = await asyncio.to_thread(_do_send)
            if res_data.get("ok"):
                message_id = res_data["result"]["message_id"]
                logger.info(f"Telegram alert sent successfully (message_id={message_id})")
                return message_id
            else:
                logger.error(f"Telegram API error: {res_data}")
                return None
        except Exception as e:
            logger.error(f"Failed to send Telegram alert: {e}")
            return None

    async def send_article_alert(self, article: dict, db: Database) -> bool:
        """
        Send an alert for a specific article and record it in the database.
        Attaches interactive inline buttons (Case Study, PoC, Checklist, Source).
        """
        article_id = article.get("id")
        if not article_id:
            logger.error("Article missing ID, cannot alert.")
            return False

        # Deduplication check
        if await db.has_alert_been_sent(article_id):
            logger.debug(f"Alert already sent for article {article_id}, skipping.")
            return False

        message = format_alert_message(article)

        # Build Interactive Inline Keyboard
        inc_id = article.get("incident_id")
        url = article.get("url")
        buttons = []

        if inc_id:
            row1 = [
                {"text": "📄 Case Study", "callback_data": f"case:{inc_id}"},
                {"text": "🛠️ Foundry PoC", "callback_data": f"poc:{inc_id}"},
            ]
            row2 = [
                {"text": "🔍 Invariant Checklist", "callback_data": f"chk:{inc_id}"},
            ]
            if url and url.startswith("http"):
                row2.append({"text": "🌐 Source", "url": url})
            buttons = [row1, row2]
        elif url and url.startswith("http"):
            buttons = [[{"text": "🌐 Read Source", "url": url}]]

        reply_markup = {"inline_keyboard": buttons} if buttons else None
        msg_id = await self.send_message(message, reply_markup=reply_markup)

        if msg_id:
            await db.record_alert(
                article_id=article_id,
                alert_type="TELEGRAM",
                telegram_message_id=msg_id,
                status="sent",
            )
            return True
        else:
            await db.record_alert(
                article_id=article_id,
                alert_type="TELEGRAM",
                status="failed",
                error="Failed to send Telegram message",
            )
            return False

    async def send_document(
        self,
        file_path: Union[str, Path],
        caption: Optional[str] = None,
        chat_id: Optional[str] = None,
    ) -> bool:
        """
        Send a local file (e.g. Markdown archive report) to Telegram via sendDocument.
        """
        target_chat = chat_id or self.chat_id
        if not self.bot_token or not target_chat:
            logger.error("Cannot send Telegram document: credentials or chat_id missing.")
            return False

        path = Path(file_path)
        if not path.exists():
            logger.error(f"Cannot send Telegram document: file not found at {path}")
            return False

        url = f"https://api.telegram.org/bot{self.bot_token}/sendDocument"
        try:
            import httpx
            async with httpx.AsyncClient(timeout=30) as client:
                with open(path, "rb") as f:
                    files = {"document": (path.name, f, "text/markdown")}
                    data = {"chat_id": target_chat}
                    if caption:
                        data["caption"] = caption
                        data["parse_mode"] = "HTML"
                    resp = await client.post(url, data=data, files=files)
                    res_json = resp.json()
                    if resp.status_code == 200 and res_json.get("ok"):
                        logger.info(f"Telegram document delivered: {path.name}")
                        return True
                    else:
                        logger.error(f"Telegram sendDocument failed: {resp.text}")
                        return False
        except Exception as e:
            logger.error(f"Failed to send Telegram document: {e}")
            return False

    async def dispatch_pending_alerts(
        self, db: Database, min_priority: int = 70, max_age_hours: Optional[int] = None
    ) -> dict:
        """
        Scan the database for unalerted high-priority articles and dispatch them.
        Filters out historical articles older than max_age_hours (default from settings).

        Args:
            db: Database instance.
            min_priority: Minimum priority score to trigger an alert (default 70).
            max_age_hours: Maximum age of article to alert on (defaults to settings.alert_max_age_hours).

        Returns:
            Summary dict with 'sent', 'failed', 'total_pending'.
        """
        if max_age_hours is None:
            max_age_hours = getattr(self.settings, "alert_max_age_hours", 400)

        pending = await db.get_unalerted_critical_articles(min_priority=min_priority)
        from app.processing.deduplication import is_article_fresh

        fresh_pending = [
            a for a in pending
            if is_article_fresh(a.get("published_at") or a.get("first_seen_at"), max_age_hours=max_age_hours)
        ]
        skipped_stale = len(pending) - len(fresh_pending)

        summary = {"sent": 0, "failed": 0, "total_pending": len(fresh_pending), "skipped_stale": skipped_stale}

        if not fresh_pending:
            logger.info(f"No fresh pending high-priority alerts to dispatch ({skipped_stale} historical skipped).")
            return summary

        logger.info(f"Dispatching {len(fresh_pending)} fresh high-priority alert(s) ({skipped_stale} historical skipped)...")

        for article in fresh_pending:
            success = await self.send_article_alert(article, db)
            if success:
                summary["sent"] += 1
            else:
                summary["failed"] += 1
            # Respect rate limits between messages
            await asyncio.sleep(1.0)

        logger.info(
            f"Alert dispatch cycle complete: {summary['sent']} sent, {summary['failed']} failed."
        )
        return summary
