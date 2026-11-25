"""
Telegram Bot Command Listener — interactive bot handlers for Web3 Security Radar.

Commands:
  /start or /help       - Directory of commands
  /ask <query>          - Ask Auditor AI technical exploit & smart contract questions
  /poc [incident_id]    - Generate/download runnable Foundry PoC Solidity test skeleton
  /watch <keyword>      - Add keyword/protocol to VIP watchlist
  /unwatch <keyword>    - Remove keyword from VIP watchlist
  /watchlist            - View all active watched keywords
  /security             - Recent 5 security exploits & case studies
  /news                 - Recent 5 major Web3 ecosystem news
  /archive_security     - Downloads reports/archive_security.md
  /archive_news         - Downloads reports/archive_news.md
  /digest               - Dispatches latest Daily Intelligence Digest
  /status               - Live database stats, classified count & source health
"""

from __future__ import annotations

import asyncio
import html
import json
import logging
from pathlib import Path
from typing import Optional

from telegram import Update, BotCommand, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
)

from app.config.settings import get_settings
from app.database.db import Database
from app.processing.archive import (
    SECURITY_ARCHIVE_PATH,
    NEWS_ARCHIVE_PATH,
    ArchiveManager,
    _format_date,
)

logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
REPORTS_DIR = ROOT_DIR / "reports"


class RadarTelegramBot:
    """
    Interactive Telegram bot application managing user queries, AI analysis,
    Foundry PoCs, watchlists, and archive downloads.
    """

    def __init__(self, db: Database, bot_token: Optional[str] = None, chat_id: Optional[str] = None):
        self.db = db
        settings = get_settings()
        self.bot_token = bot_token or settings.telegram_bot_token
        self.configured_chat_id = str(chat_id or settings.telegram_chat_id or "")
        self.app: Optional[Application] = None
        self._is_running = False

    def _is_authorized(self, update: Update) -> bool:
        """Security check: ensure message originates from configured chat ID."""
        if not self.configured_chat_id:
            return True
        if not update.effective_chat:
            return False
        return str(update.effective_chat.id) == self.configured_chat_id

    async def _handle_unauthorized(self, update: Update) -> None:
        if update.message:
            await update.message.reply_text("⛔ Unauthorized access. This bot is configured for private use.")

    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handler for /start and /help."""
        if not self._is_authorized(update):
            await self._handle_unauthorized(update)
            return

        text = (
            "🛡️ <b>Web3 Security Radar Bot</b>\n\n"
            "Personal real-time intelligence for Web3 security auditors & researchers.\n\n"
            "<b>Auditor Intelligence:</b>\n"
            "• /ask &lt;question&gt; — Ask Auditor AI technical exploit questions\n"
            "• /search &lt;keyword&gt; [sort:loss|severity|date] — Search past & present exploits\n"
            "• /incident &lt;id&gt; — View incident card with direct original source link\n"
            "• /poc [id] — Generate runnable Foundry test skeleton\n"
            "• /watch &lt;keyword&gt; — Add VIP alert keyword (e.g. /watch flash loan)\n"
            "• /watchlist — View active VIP alert keywords\n"
            "• /unwatch &lt;keyword&gt; — Remove keyword from watchlist\n\n"
            "<b>Radar Feeds & Archives:</b>\n"
            "• /security — View recent 5 security exploits & case studies\n"
            "• /news — View recent 5 major Web3 ecosystem news\n"
            "• /archive_security — Download full <code>archive_security.md</code> file\n"
            "• /archive_news — Download full <code>archive_news.md</code> file\n"
            "• /digest — Generate & dispatch latest Daily Intelligence Digest\n"
            "• /status — View live database counts & system health\n"
            "• /help — Show this command reference"
        )
        if update.message:
            await update.message.reply_text(text, parse_mode="HTML")

    async def ask_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handler for /ask — answers auditor questions via Gemini & local exploit database."""
        if not self._is_authorized(update):
            await self._handle_unauthorized(update)
            return

        query = " ".join(context.args) if context.args else ""
        if not query.strip():
            if update.message:
                await update.message.reply_text(
                    "💡 <b>Usage:</b> <code>/ask &lt;your smart contract question&gt;</code>\n"
                    "Example: <code>/ask How did the Liquid Network hack happen?</code>",
                    parse_mode="HTML",
                )
            return

        status_msg = None
        if update.message:
            status_msg = await update.message.reply_text(
                "⚡ <i>Auditor AI is analyzing smart-contract vulnerability patterns...</i>",
                parse_mode="HTML",
            )

        from app.ai.qa import ask_auditor
        response_text = await ask_auditor(query, self.db)

        if len(response_text) <= 4000:
            if status_msg:
                try:
                    await status_msg.edit_text(response_text, parse_mode="HTML", disable_web_page_preview=True)
                except Exception:
                    if update.message:
                        await update.message.reply_text(response_text, parse_mode="HTML", disable_web_page_preview=True)
            elif update.message:
                await update.message.reply_text(response_text, parse_mode="HTML", disable_web_page_preview=True)
        else:
            if status_msg:
                try:
                    await status_msg.delete()
                except Exception:
                    pass
            for i in range(0, len(response_text), 3800):
                chunk = response_text[i:i + 3800]
                if update.message:
                    await update.message.reply_text(chunk, parse_mode="HTML", disable_web_page_preview=True)

    async def poc_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handler for /poc [incident_id] — generates or retrieves Foundry PoC test file."""
        if not self._is_authorized(update):
            await self._handle_unauthorized(update)
            return

        inc_id = None
        if context.args and context.args[0].isdigit():
            inc_id = int(context.args[0])
        else:
            # Default to latest high/critical incident
            cursor = await self.db.conn.execute(
                "SELECT id, title, protocol FROM incidents WHERE estimated_loss_usd > 0 ORDER BY id DESC LIMIT 1"
            )
            row = await cursor.fetchone()
            if row:
                inc_id = row[0]

        if not inc_id:
            if update.message:
                await update.message.reply_text(
                    "Usage: <code>/poc &lt;incident_id&gt;</code>\nExample: <code>/poc 1</code>",
                    parse_mode="HTML",
                )
            return

        if update.message:
            await update.message.reply_text(
                f"🛠️ <i>Generating Foundry PoC test skeleton for Incident #{inc_id}...</i>",
                parse_mode="HTML",
            )

        from app.ai.poc_generator import generate_foundry_poc
        poc_path = await generate_foundry_poc(inc_id, self.db)
        if poc_path and poc_path.exists():
            with open(poc_path, "rb") as f:
                if update.message:
                    await update.message.reply_document(
                        document=f,
                        filename=poc_path.name,
                        caption=f"🛠️ <b>Foundry PoC Test:</b> <code>{poc_path.name}</code>\n"
                                f"Run with: <code>forge test --match-test test_exploit -vvvv</code>",
                        parse_mode="HTML",
                    )
        else:
            if update.message:
                await update.message.reply_text(f"❌ Failed to generate Foundry PoC for Incident #{inc_id}.")

    async def search_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handler for /search <keyword> [sort:loss|severity|oldest|date] — search database for historical or present exploits."""
        if not self._is_authorized(update):
            await self._handle_unauthorized(update)
            return

        raw_args = context.args or []
        sort_mode = "date"
        clean_terms = []
        for arg in raw_args:
            arg_lower = arg.lower()
            if arg_lower.startswith("sort:"):
                sort_val = arg_lower.split(":", 1)[1]
                if sort_val in ("loss", "usd", "amount"):
                    sort_mode = "loss"
                elif sort_val in ("sev", "severity", "crit"):
                    sort_mode = "severity"
                elif sort_val in ("old", "oldest", "asc"):
                    sort_mode = "oldest"
                else:
                    sort_mode = "date"
            else:
                clean_terms.append(arg)

        query = " ".join(clean_terms).strip()
        if not query:
            if update.message:
                await update.message.reply_text(
                    "💡 <b>Usage:</b> <code>/search &lt;keyword or protocol&gt; [sort:loss|severity|date]</code>\n\n"
                    "Examples:\n"
                    "• <code>/search Curve</code>\n"
                    "• <code>/search 2021 sort:loss</code>\n"
                    "• <code>/search reentrancy sort:severity</code>\n"
                    "• <code>/search Nomad</code>\n"
                    "• <code>/incident 1005</code> — View specific incident details",
                    parse_mode="HTML",
                )
            return

        pattern = f"%{query}%"

        # Dynamic sorting
        if sort_mode == "loss":
            order_by_sql = "COALESCE(i.estimated_loss_usd, 0) DESC, event_date DESC"
        elif sort_mode == "severity":
            order_by_sql = """
                CASE i.severity 
                    WHEN 'CRITICAL' THEN 1 
                    WHEN 'HIGH' THEN 2 
                    WHEN 'MEDIUM' THEN 3 
                    WHEN 'LOW' THEN 4 
                    ELSE 5 
                END ASC, COALESCE(i.estimated_loss_usd, 0) DESC
            """
        elif sort_mode == "oldest":
            order_by_sql = "event_date ASC, i.id ASC"
        else:
            order_by_sql = "event_date DESC, i.id DESC"

        cursor = await self.db.conn.execute(
            f"""
            SELECT i.id, i.title, i.protocol, i.chain, i.attack_type, 
                   i.estimated_loss_usd, i.severity, 
                   COALESCE(MIN(a.published_at), i.first_seen_at) as event_date,
                   MIN(a.url) as primary_url
            FROM incidents i
            LEFT JOIN articles a ON a.incident_id = i.id
            WHERE i.title LIKE ? OR i.protocol LIKE ? OR i.attack_type LIKE ? 
               OR a.published_at LIKE ? OR a.title LIKE ? OR i.first_seen_at LIKE ? OR a.url LIKE ?
            GROUP BY i.id
            ORDER BY {order_by_sql}
            LIMIT 5
            """,
            (pattern, pattern, pattern, pattern, pattern, pattern, pattern),
        )
        rows = await cursor.fetchall()

        if not rows:
            if update.message:
                await update.message.reply_text(
                    f"🔍 No incident records found in local database for: <code>{html.escape(query)}</code>\n\n"
                    f"💡 <i>Tip: You can ask Auditor AI about any past hack in Web3 history via:</i>\n"
                    f"<code>/ask What happened in the {html.escape(query)} hack?</code>",
                    parse_mode="HTML",
                )
            return

        if update.message:
            await update.message.reply_text(
                f"🔍 <b>Found {len(rows)} matching incident(s) for '<code>{html.escape(query)}</code>' (sorted by {sort_mode}):</b>",
                parse_mode="HTML",
            )

        for row in rows:
            inc_id, title, proto, chain, attack_type, loss, severity, event_date, primary_url = row
            loss_txt = f"${loss:,.0f}" if loss and loss > 0 else "Undisclosed"
            date_str = (event_date or "")[:10] or "Historical"

            msg = (
                f"🛡️ <b>Incident #{inc_id}: {html.escape(title)}</b>\n"
                f"📅 <b>Date:</b> <code>{date_str}</code> | 🎯 <b>Protocol:</b> {html.escape(proto or 'N/A')}\n"
                f"💰 <b>Loss:</b> {loss_txt} | 🚨 <b>Severity:</b> <code>{severity}</code>"
            )

            keyboard = []
            row1 = []
            if primary_url:
                row1.append(InlineKeyboardButton("🌐 Original Source ↗", url=primary_url))
            row1.append(InlineKeyboardButton("📄 Case Study", callback_data=f"case:{inc_id}"))
            keyboard.append(row1)

            keyboard.append([
                InlineKeyboardButton("🛠️ Foundry PoC", callback_data=f"poc:{inc_id}"),
                InlineKeyboardButton("🔍 Invariants", callback_data=f"chk:{inc_id}"),
            ])
            reply_markup = InlineKeyboardMarkup(keyboard)

            if update.message:
                await update.message.reply_text(
                    msg,
                    parse_mode="HTML",
                    reply_markup=reply_markup,
                    disable_web_page_preview=True,
                )

    async def incident_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handler for /incident <id> — display single incident by ID with direct source link."""
        if not self._is_authorized(update):
            await self._handle_unauthorized(update)
            return

        if not context.args or not context.args[0].isdigit():
            if update.message:
                await update.message.reply_text("Usage: <code>/incident &lt;id&gt;</code>\nExample: <code>/incident 1005</code>", parse_mode="HTML")
            return

        inc_id = int(context.args[0])
        inc = await self.db.get_incident(inc_id)
        if not inc:
            if update.message:
                await update.message.reply_text(f"❌ Incident #{inc_id} not found in database.", parse_mode="HTML")
            return

        articles = await self.db.get_incident_articles(inc_id)
        primary_url = articles[0].get("url") if articles else None
        loss = inc.get("estimated_loss_usd")
        loss_txt = f"${loss:,.0f}" if loss and loss > 0 else "Undisclosed"
        date_str = (inc.get("first_seen_at") or "")[:10] or "Historical"

        msg = (
            f"🛡️ <b>Incident #{inc_id}: {html.escape(inc.get('title') or 'Incident')}</b>\n"
            f"📅 <b>Date:</b> <code>{date_str}</code> | 🎯 <b>Protocol:</b> <code>{html.escape(inc.get('protocol') or 'N/A')}</code>\n"
            f"💰 <b>Loss:</b> {loss_txt} | 🚨 <b>Severity:</b> <code>{inc.get('severity', 'INFO')}</code>\n"
            f"🏷️ <b>Vector:</b> <code>{html.escape(str(inc.get('attack_type') or 'Unspecified'))}</code>"
        )
        if inc.get("deep_analysis"):
            msg += f"\n\n<b>Analysis:</b>\n{html.escape(str(inc['deep_analysis'])[:500])}..."
        elif articles and articles[0].get("summary"):
            msg += f"\n\n<b>Summary:</b>\n<i>{html.escape(articles[0]['summary'])}</i>"

        keyboard = []
        row1 = []
        if primary_url:
            row1.append(InlineKeyboardButton("🌐 Original Source ↗", url=primary_url))
        row1.append(InlineKeyboardButton("📄 Case Study", callback_data=f"case:{inc_id}"))
        keyboard.append(row1)

        keyboard.append([
            InlineKeyboardButton("🛠️ Foundry PoC", callback_data=f"poc:{inc_id}"),
            InlineKeyboardButton("🔍 Invariants", callback_data=f"chk:{inc_id}"),
        ])

        if update.message:
            await update.message.reply_text(
                msg,
                parse_mode="HTML",
                reply_markup=InlineKeyboardMarkup(keyboard),
                disable_web_page_preview=True,
            )

    async def watch_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handler for /watch <keyword> — adds topic to VIP watchlist."""
        if not self._is_authorized(update):
            await self._handle_unauthorized(update)
            return

        if not context.args:
            if update.message:
                await update.message.reply_text(
                    "Usage: <code>/watch &lt;protocol or keyword&gt;</code>\n"
                    "Examples:\n• <code>/watch flash loan</code>\n• <code>/watch Aave</code>\n• <code>/watch reentrancy</code>",
                    parse_mode="HTML",
                )
            return

        keyword = " ".join(context.args).strip()
        added = await self.db.add_watchlist_keyword(keyword)
        if added:
            if update.message:
                await update.message.reply_text(
                    f"🎯 <b>Added to VIP Watchlist:</b> <code>{html.escape(keyword)}</code>\n"
                    f"You will receive immediate highlighted alerts when this topic appears in any feed.",
                    parse_mode="HTML",
                )
        else:
            if update.message:
                await update.message.reply_text(
                    f"ℹ️ <code>{html.escape(keyword)}</code> is already in your watchlist.",
                    parse_mode="HTML",
                )

    async def unwatch_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handler for /unwatch <keyword> — removes topic from VIP watchlist."""
        if not self._is_authorized(update):
            await self._handle_unauthorized(update)
            return

        if not context.args:
            if update.message:
                await update.message.reply_text("Usage: <code>/unwatch &lt;keyword&gt;</code>", parse_mode="HTML")
            return

        keyword = " ".join(context.args).strip()
        removed = await self.db.remove_watchlist_keyword(keyword)
        if removed:
            if update.message:
                await update.message.reply_text(
                    f"🗑️ Removed <code>{html.escape(keyword)}</code> from your watchlist.",
                    parse_mode="HTML",
                )
        else:
            if update.message:
                await update.message.reply_text(
                    f"ℹ️ <code>{html.escape(keyword)}</code> was not found in your watchlist.",
                    parse_mode="HTML",
                )

    async def watchlist_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handler for /watchlist — displays all active watched keywords."""
        if not self._is_authorized(update):
            await self._handle_unauthorized(update)
            return

        keywords = await self.db.get_watchlist_keywords()
        if not keywords:
            if update.message:
                await update.message.reply_text(
                    "📋 <b>Watchlist is currently empty.</b>\n"
                    "Add keywords to monitor via: <code>/watch &lt;keyword&gt;</code>\n"
                    "Example: <code>/watch flash loan</code>",
                    parse_mode="HTML",
                )
            return

        lines = [
            "🎯 <b>Active Protocol & Vulnerability Watchlist:</b>",
            "",
        ]
        for i, kw in enumerate(keywords, 1):
            lines.append(f"{i}. <code>{html.escape(kw)}</code>")
        lines.append("")
        lines.append("<i>To remove an item, send: /unwatch &lt;keyword&gt;</i>")

        if update.message:
            await update.message.reply_text("\n".join(lines), parse_mode="HTML")

    async def security_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handler for /security — returns top 5 recent security exploits."""
        if not self._is_authorized(update):
            await self._handle_unauthorized(update)
            return

        cursor = await self.db.conn.execute(
            """
            SELECT a.*, s.name as source_name
            FROM articles a
            JOIN sources s ON a.source_id = s.id
            WHERE a.classified_at IS NOT NULL
              AND (a.category IN ('CRITICAL_SECURITY', 'HIGH_SECURITY', 'SECURITY_RESEARCH', 'DEFI_EXPLOIT')
                   OR a.estimated_loss_usd > 0
                   OR a.security_relevance >= 60)
            ORDER BY COALESCE(a.published_at, a.first_seen_at) DESC
            LIMIT 5
            """
        )
        columns = [desc[0] for desc in cursor.description]
        rows = await cursor.fetchall()
        items = [dict(zip(columns, row)) for row in rows]

        if not items:
            if update.message:
                await update.message.reply_text("No security incidents recorded yet.")
            return

        msg_lines = [
            "🛡️ <b>Recent Web3 Security Exploits & Research:</b>",
            "",
        ]

        for i, item in enumerate(items, 1):
            title = html.escape(item.get("title") or "Untitled")
            url = item.get("url") or "#"
            date = _format_date(item.get("published_at") or item.get("first_seen_at"))
            proto = html.escape(item.get("protocol") or "Protocol")
            loss = item.get("estimated_loss_usd")
            loss_txt = f"${loss:,.0f}" if loss and loss > 0 else "Undisclosed"
            summary = html.escape(item.get("summary") or "")

            msg_lines.append(f"<b>{i}. {title}</b>")
            msg_lines.append(f"📅 <code>{date}</code> | 🎯 <b>Protocol:</b> {proto} | 💰 <b>Loss:</b> {loss_txt}")
            if summary:
                msg_lines.append(f"<i>{summary[:160]}...</i>")
            msg_lines.append(f'🔗 <a href="{html.escape(url)}">Read Report</a>')
            msg_lines.append("")

        msg_lines.append("💡 <i>Tip: Send /archive_security to download the complete archive file.</i>")

        if update.message:
            await update.message.reply_text(
                "\n".join(msg_lines),
                parse_mode="HTML",
                disable_web_page_preview=True,
            )

    async def news_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handler for /news — returns top 5 recent major Web3 ecosystem news."""
        if not self._is_authorized(update):
            await self._handle_unauthorized(update)
            return

        cursor = await self.db.conn.execute(
            """
            SELECT a.*, s.name as source_name
            FROM articles a
            JOIN sources s ON a.source_id = s.id
            WHERE a.classified_at IS NOT NULL
              AND a.category IN ('MAJOR_WEB3_NEWS', 'PROTOCOL_UPDATE', 'REGULATION', 'GENERAL_NEWS')
            ORDER BY COALESCE(a.published_at, a.first_seen_at) DESC
            LIMIT 5
            """
        )
        columns = [desc[0] for desc in cursor.description]
        rows = await cursor.fetchall()
        items = [dict(zip(columns, row)) for row in rows]

        if not items:
            if update.message:
                await update.message.reply_text("No major news articles recorded yet.")
            return

        msg_lines = [
            "🌐 <b>Recent Major Web3 Ecosystem News:</b>",
            "",
        ]

        for i, item in enumerate(items, 1):
            title = html.escape(item.get("title") or "Untitled")
            url = item.get("url") or "#"
            date = _format_date(item.get("published_at") or item.get("first_seen_at"))
            cat = html.escape(item.get("category") or "NEWS")
            source = html.escape(item.get("source_name") or "Source")
            summary = html.escape(item.get("summary") or "")

            msg_lines.append(f"<b>{i}. {title}</b>")
            msg_lines.append(f"📅 <code>{date}</code> | 🏷️ <b>Category:</b> {cat} | 📰 <b>Source:</b> {source}")
            if summary:
                msg_lines.append(f"<i>{summary[:160]}...</i>")
            msg_lines.append(f'🔗 <a href="{html.escape(url)}">Read Article</a>')
            msg_lines.append("")

        msg_lines.append("💡 <i>Tip: Send /archive_news to download the complete news archive file.</i>")

        if update.message:
            await update.message.reply_text(
                "\n".join(msg_lines),
                parse_mode="HTML",
                disable_web_page_preview=True,
            )

    async def archive_security_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handler for /archive_security — uploads reports/archive_security.md to user."""
        if not self._is_authorized(update):
            await self._handle_unauthorized(update)
            return

        archive_mgr = ArchiveManager()
        if not archive_mgr.security_path.exists():
            await archive_mgr.backfill_archives(self.db)

        if not archive_mgr.security_path.exists():
            if update.message:
                await update.message.reply_text("Security archive file does not exist yet.")
            return

        if update.message:
            await update.message.reply_text("⏳ Uploading Web3 Security Knowledge Archive...")
            with open(archive_mgr.security_path, "rb") as f:
                await update.message.reply_document(
                    document=f,
                    filename="archive_security.md",
                    caption="🛡️ <b>Web3 Security Intelligence Archive</b>\nComplete markdown log of exploits, audits, and case studies.",
                    parse_mode="HTML",
                )

    async def archive_news_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handler for /archive_news — uploads reports/archive_news.md to user."""
        if not self._is_authorized(update):
            await self._handle_unauthorized(update)
            return

        archive_mgr = ArchiveManager()
        if not archive_mgr.news_path.exists():
            await archive_mgr.backfill_archives(self.db)

        if not archive_mgr.news_path.exists():
            if update.message:
                await update.message.reply_text("News archive file does not exist yet.")
            return

        if update.message:
            await update.message.reply_text("⏳ Uploading Web3 Ecosystem News Archive...")
            with open(archive_mgr.news_path, "rb") as f:
                await update.message.reply_document(
                    document=f,
                    filename="archive_news.md",
                    caption="🌐 <b>Major Web3 Ecosystem News Archive</b>\nComplete markdown log of protocol updates and regulations.",
                    parse_mode="HTML",
                )

    async def digest_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handler for /digest — generates and sends Daily Security Digest immediately."""
        if not self._is_authorized(update):
            await self._handle_unauthorized(update)
            return

        if update.message:
            await update.message.reply_text("⏳ Compiling and dispatching latest Daily Intelligence Digest...")

        try:
            from app.digest.daily import run_daily_digest
            report_path, telegram_ids = await run_daily_digest(
                db=self.db,
                target_date=None,
                send_telegram=True,
                force=True,
            )
            if report_path and telegram_ids:
                if update.message:
                    await update.message.reply_text(
                        f"✅ <b>Daily Digest Dispatched!</b>\nSaved to <code>{report_path.name}</code> with {len(telegram_ids)} Telegram card(s).",
                        parse_mode="HTML",
                    )
            elif report_path:
                if update.message:
                    await update.message.reply_text(
                        f"✅ Digest compiled to <code>{report_path.name}</code> (no new events for this period).",
                        parse_mode="HTML",
                    )
            else:
                if update.message:
                    await update.message.reply_text("Could not generate digest. Check logs.")
        except Exception as e:
            logger.error(f"Error executing /digest command: {e}", exc_info=True)
            if update.message:
                await update.message.reply_text(f"❌ Error generating digest: {e}")

    async def status_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handler for /status — displays live system metrics."""
        if not self._is_authorized(update):
            await self._handle_unauthorized(update)
            return

        total = await self.db.get_article_count()
        unclass = len(await self.db.get_unclassified_articles(limit=9999))
        classified = total - unclass
        active_inc = len(await self.db.get_active_incidents(hours=99999))
        stats = await self.db.get_source_stats()
        active_rss = [s for s in stats if s.get("is_active") and "Historical Archive" not in s.get("name", "")]
        rss_ok = sum(1 for s in active_rss if s.get("last_fetched_at") and not s.get("last_error"))
        rss_pct = round((rss_ok / len(active_rss)) * 100) if active_rss else 0
        hist_sources = [s for s in stats if "Historical Archive" in s.get("name", "")]
        hist_count = hist_sources[0]["article_count"] if hist_sources else 0
        hist_label = f"DeFiHackLabs Archive ({hist_count:,} exploits)" if hist_count else "Not imported (run backfill-history)"
        watchlist = await self.db.get_watchlist_keywords()

        status_text = (
            "📊 <b>Web3 Security Radar — Live Status</b>\n\n"
            f"• <b>Total Articles Collected:</b> <code>{total}</code>\n"
            f"• <b>Classified by AI:</b> <code>{classified}</code>\n"
            f"• <b>Pending Classification:</b> <code>{unclass}</code>\n"
            f"• <b>Security Incidents Tracked:</b> <code>{active_inc}</code>\n"
            f"• <b>VIP Watchlist Keywords:</b> <code>{len(watchlist)}</code>\n"
            f"• <b>Active RSS Feeds:</b> <code>{rss_ok}/{len(active_rss)} healthy ({rss_pct}%)</code>\n"
            f"• <b>Historical Datasets:</b> <code>{hist_label}</code>\n\n"
            "✅ <i>Pipeline daemon, bot listener, and web UI are running normally.</i>"
        )
        if update.message:
            await update.message.reply_text(status_text, parse_mode="HTML")

    async def button_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle inline keyboard taps (Case Study, PoC, Checklist)."""
        query = update.callback_query
        if not query or not query.data:
            return
        try:
            await query.answer()
        except Exception:
            pass

        data = query.data
        chat_id = query.message.chat_id if query.message else None

        if data.startswith("case:"):
            inc_id = int(data.split(":")[1])
            inc = await self.db.get_incident(inc_id)
            proto = (inc.get("protocol") or "incident").lower() if inc else "incident"
            slug = "".join(c for c in proto if c.isalnum() or c == "_")
            report_path = REPORTS_DIR / f"incident_{inc_id}_{slug}.md"
            if not report_path.exists():
                from app.ai.analyzer import run_incident_deep_analysis
                try:
                    report_path = await run_incident_deep_analysis(inc_id, self.db, send_telegram=False)
                except Exception:
                    report_path = None

            if report_path and report_path.exists():
                with open(report_path, "rb") as f:
                    await context.bot.send_document(
                        chat_id=chat_id,
                        document=f,
                        filename=report_path.name,
                        caption=f"📄 <b>Case Study Report: Incident #{inc_id}</b>",
                        parse_mode="HTML",
                    )
            else:
                # Provide a rich incident dossier card with original source URL
                articles = await self.db.get_incident_articles(inc_id)
                primary_url = articles[0].get("url") if articles else None
                title = inc.get("title") or "Incident Dossier"
                date_str = (inc.get("first_seen_at") or "")[:10] or "Historical"
                loss = inc.get("estimated_loss_usd")
                loss_str = f"${loss:,.0f}" if loss else "Undisclosed"
                proto_name = inc.get("protocol") or "Ecosystem"
                vector = inc.get("attack_type") or "Unspecified"

                lines = [
                    f"📄 <b>Incident Dossier #{inc_id}: {html.escape(title)}</b>",
                    f"📅 <b>Date:</b> <code>{date_str}</code> | 🎯 <b>Protocol:</b> <code>{html.escape(proto_name)}</code>",
                    f"💰 <b>Loss:</b> {loss_str} | 🚨 <b>Severity:</b> <code>{inc.get('severity', 'INFO')}</code>",
                    f"🏷️ <b>Vector:</b> <code>{html.escape(str(vector))}</code>",
                    "",
                ]
                if inc.get("deep_analysis"):
                    lines.append(f"<b>Analysis:</b>\n{html.escape(str(inc['deep_analysis'])[:500])}...\n")
                elif articles and articles[0].get("summary"):
                    lines.append(f"<b>Summary:</b>\n<i>{html.escape(articles[0]['summary'])}</i>\n")

                kb = []
                row1 = []
                if primary_url:
                    row1.append(InlineKeyboardButton("🌐 Original Source ↗", url=primary_url))
                row1.append(InlineKeyboardButton("🛠️ Foundry PoC", callback_data=f"poc:{inc_id}"))
                kb.append(row1)

                await context.bot.send_message(
                    chat_id=chat_id,
                    text="\n".join(lines),
                    parse_mode="HTML",
                    reply_markup=InlineKeyboardMarkup(kb),
                    disable_web_page_preview=True,
                )

        elif data.startswith("poc:"):
            inc_id = int(data.split(":")[1])
            await context.bot.send_message(
                chat_id=chat_id,
                text=f"🛠️ <i>Generating Foundry PoC test skeleton for Incident #{inc_id}...</i>",
                parse_mode="HTML",
            )
            from app.ai.poc_generator import generate_foundry_poc
            poc_path = await generate_foundry_poc(inc_id, self.db)
            if poc_path and poc_path.exists():
                with open(poc_path, "rb") as f:
                    await context.bot.send_document(
                        chat_id=chat_id,
                        document=f,
                        filename=poc_path.name,
                        caption=f"🛠️ <b>Foundry PoC Skeleton:</b> <code>{poc_path.name}</code>\n"
                                f"Run with: <code>forge test --match-test test_exploit -vvvv</code>",
                        parse_mode="HTML",
                    )
            else:
                await context.bot.send_message(chat_id=chat_id, text=f"Could not generate PoC for Incident #{inc_id}.")

        elif data.startswith("chk:"):
            inc_id = int(data.split(":")[1])
            inc = await self.db.get_incident(inc_id)
            title = inc.get("title") or "Incident"
            proto = inc.get("protocol") or "Protocol"
            deep_analysis_raw = inc.get("deep_analysis")

            msg_lines = [
                f"🔍 <b>Auditor Checklist & Invariants — Incident #{inc_id}</b>",
                f"<b>{html.escape(title)}</b> (<i>{html.escape(proto)}</i>)",
                "",
            ]
            if deep_analysis_raw:
                try:
                    d_json = json.loads(deep_analysis_raw)
                    lessons = d_json.get("auditor_lessons", [])
                    invs = d_json.get("mitigations_and_invariants", [])

                    if lessons:
                        msg_lines.append("📋 <b>Audit Focus Areas:</b>")
                        for lesson in lessons[:3]:
                            msg_lines.append(f"• {html.escape(lesson)}")
                        msg_lines.append("")

                    if invs:
                        msg_lines.append("🛡️ <b>Key Invariants:</b>")
                        for inv in invs[:3]:
                            msg_lines.append(f"• <code>{html.escape(inv)}</code>")
                except Exception:
                    msg_lines.append("Review protocol states for reentrancy, oracle divergence, and fee accounting integrity.")
            else:
                msg_lines.append("Ensure balance invariance, non-reentrancy on state mutations, and strict oracle freshness validation.")

            await context.bot.send_message(chat_id=chat_id, text="\n".join(msg_lines), parse_mode="HTML")

    async def start(self) -> None:
        """Initialize and start polling for bot commands asynchronously."""
        if not self.bot_token:
            logger.warning("Telegram bot token not configured. Bot command listener disabled.")
            return

        self.app = ApplicationBuilder().token(self.bot_token).build()

        # Register command handlers
        self.app.add_handler(CommandHandler(["start", "help"], self.start_command))
        self.app.add_handler(CommandHandler("ask", self.ask_command))
        self.app.add_handler(CommandHandler("search", self.search_command))
        self.app.add_handler(CommandHandler("incident", self.incident_command))
        self.app.add_handler(CommandHandler("poc", self.poc_command))
        self.app.add_handler(CommandHandler("watch", self.watch_command))
        self.app.add_handler(CommandHandler("unwatch", self.unwatch_command))
        self.app.add_handler(CommandHandler("watchlist", self.watchlist_command))
        self.app.add_handler(CommandHandler("security", self.security_command))
        self.app.add_handler(CommandHandler("news", self.news_command))
        self.app.add_handler(CommandHandler("archive_security", self.archive_security_command))
        self.app.add_handler(CommandHandler("archive_news", self.archive_news_command))
        self.app.add_handler(CommandHandler("digest", self.digest_command))
        self.app.add_handler(CommandHandler("status", self.status_command))

        # Register inline button handler
        self.app.add_handler(CallbackQueryHandler(self.button_callback))

        await self.app.initialize()

        # Register quick-menu command buttons in Telegram client
        try:
            menu_commands = [
                BotCommand("search", "Search past & present exploits in database"),
                BotCommand("incident", "View specific incident details by ID"),
                BotCommand("ask", "Ask Auditor AI about any exploit or invariant"),
                BotCommand("poc", "Generate Foundry PoC test skeleton"),
                BotCommand("security", "Top 5 recent security exploits & research"),
                BotCommand("news", "Top 5 recent major Web3 ecosystem news"),
                BotCommand("watch", "Add keyword/protocol to VIP alert watchlist"),
                BotCommand("watchlist", "View your active VIP alert watchlist"),
                BotCommand("archive_security", "Download complete Security Archive file"),
                BotCommand("archive_news", "Download complete Web3 News Archive file"),
                BotCommand("digest", "Dispatch latest Daily Intelligence Digest"),
                BotCommand("status", "Show live system metrics & health"),
                BotCommand("help", "Show all commands"),
            ]
            await self.app.bot.set_my_commands(menu_commands)
        except Exception as e:
            logger.debug(f"Could not set Telegram menu commands: {e}")

        await self.app.start()
        await self.app.updater.start_polling(drop_pending_updates=True)
        self._is_running = True
        logger.info("[OK] Telegram Bot Command Listener started successfully.")

    async def stop(self) -> None:
        """Gracefully stop the bot listener."""
        if self._is_running and self.app:
            try:
                if self.app.updater and self.app.updater.running:
                    await self.app.updater.stop()
                await self.app.stop()
                await self.app.shutdown()
            except Exception as e:
                logger.warning(f"Error during bot shutdown: {e}")
            finally:
                self._is_running = False
                logger.info("Telegram Bot Command Listener stopped.")
