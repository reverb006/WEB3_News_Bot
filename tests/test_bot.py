"""
Unit tests for the RadarTelegramBot command handlers and authorization gate.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
import pytest

from app.alerts.bot import RadarTelegramBot
from app.database.db import Database
from app.models.schemas import SourceConfig, SourceType


def make_mock_update(chat_id: int, message_text: str = "/start"):
    update = MagicMock()
    update.effective_chat.id = chat_id
    update.message = MagicMock()
    update.message.text = message_text
    update.message.reply_text = AsyncMock()
    update.message.reply_document = AsyncMock()
    return update


@pytest.mark.asyncio
async def test_bot_auth_check():
    db = Database(":memory:")
    await db.initialize()

    bot = RadarTelegramBot(db=db, bot_token="test_token", chat_id="123456789")

    # Authorized user
    auth_update = make_mock_update(chat_id=123456789, message_text="/start")
    assert bot._is_authorized(auth_update) is True

    # Unauthorized user
    unauth_update = make_mock_update(chat_id=987654321, message_text="/start")
    assert bot._is_authorized(unauth_update) is False

    await bot.start_command(unauth_update, MagicMock())
    unauth_update.message.reply_text.assert_called_once()
    assert "Unauthorized" in unauth_update.message.reply_text.call_args[0][0]

    await db.close()


@pytest.mark.asyncio
async def test_bot_start_command():
    db = Database(":memory:")
    await db.initialize()

    bot = RadarTelegramBot(db=db, bot_token="test_token", chat_id="123456789")
    update = make_mock_update(chat_id=123456789, message_text="/start")

    await bot.start_command(update, MagicMock())

    update.message.reply_text.assert_called_once()
    reply = update.message.reply_text.call_args[0][0]
    assert "Web3 Security Radar Bot" in reply
    assert "/security" in reply
    assert "/news" in reply
    assert "/archive_security" in reply

    await db.close()


@pytest.mark.asyncio
async def test_bot_security_and_news_commands():
    db = Database(":memory:")
    await db.initialize()

    src = SourceConfig(
        name="PeckShield",
        url="http://p.com",
        source_type=SourceType.SECURITY_COMPANY,
        collector_type="rss",
    )
    src_id = await db.upsert_source(src)

    # Insert security article
    await db.conn.execute(
        """
        INSERT INTO articles (url, url_hash, title, source_id, source_type, category, severity,
                              priority_score, estimated_loss_usd, protocol, summary, classified_at, first_seen_at)
        VALUES ('http://hacked.com', 'h1', 'DeFi Pool Drained', ?, 'SECURITY_COMPANY',
                'CRITICAL_SECURITY', 'CRITICAL', 95, 10000000.0, 'CoolPool', 'Reentrancy flaw', datetime('now'), datetime('now'))
        """,
        (src_id,),
    )
    # Insert news article
    await db.conn.execute(
        """
        INSERT INTO articles (url, url_hash, title, source_id, source_type, category, severity,
                              priority_score, summary, classified_at, first_seen_at)
        VALUES ('http://news.com', 'h2', 'EIP-7702 Activated', ?, 'NEWS_MEDIA',
                'PROTOCOL_UPDATE', 'LOW', 25, 'Account abstraction upgrade', datetime('now'), datetime('now'))
        """,
        (src_id,),
    )
    await db.conn.commit()

    bot = RadarTelegramBot(db=db, bot_token="test_token", chat_id="123456789")

    # Test /security
    sec_update = make_mock_update(chat_id=123456789, message_text="/security")
    await bot.security_command(sec_update, MagicMock())
    sec_update.message.reply_text.assert_called_once()
    sec_reply = sec_update.message.reply_text.call_args[0][0]
    assert "DeFi Pool Drained" in sec_reply
    assert "CoolPool" in sec_reply
    assert "$10,000,000" in sec_reply

    # Test /news
    news_update = make_mock_update(chat_id=123456789, message_text="/news")
    await bot.news_command(news_update, MagicMock())
    news_update.message.reply_text.assert_called_once()
    news_reply = news_update.message.reply_text.call_args[0][0]
    assert "EIP-7702 Activated" in news_reply
    assert "Account abstraction" in news_reply

    await db.close()


@pytest.mark.asyncio
async def test_bot_watchlist_commands():
    db = Database(":memory:")
    await db.initialize()

    bot = RadarTelegramBot(db=db, bot_token="test_token", chat_id="123456789")

    # 1. /watch flash loan
    ctx_add = MagicMock()
    ctx_add.args = ["flash", "loan"]
    update_add = make_mock_update(chat_id=123456789)
    await bot.watch_command(update_add, ctx_add)
    update_add.message.reply_text.assert_called_once()
    assert "flash loan" in update_add.message.reply_text.call_args[0][0]

    # 2. /watchlist
    ctx_list = MagicMock()
    update_list = make_mock_update(chat_id=123456789)
    await bot.watchlist_command(update_list, ctx_list)
    update_list.message.reply_text.assert_called_once()
    assert "flash loan" in update_list.message.reply_text.call_args[0][0]

    # 3. /unwatch flash loan
    ctx_del = MagicMock()
    ctx_del.args = ["flash", "loan"]
    update_del = make_mock_update(chat_id=123456789)
    await bot.unwatch_command(update_del, ctx_del)
    update_del.message.reply_text.assert_called_once()
    assert "Removed" in update_del.message.reply_text.call_args[0][0]

    await db.close()


@pytest.mark.asyncio
async def test_bot_button_callback():
    db = Database(":memory:")
    await db.initialize()

    inc_id = await db.create_incident(
        title="Vyper Reentrancy Hack",
        protocol="Curve",
        chain=["Ethereum"],
        attack_type=["REENTRANCY"],
        estimated_loss_usd=60_000_000.0,
        severity="CRITICAL",
        status="active",
    )

    bot = RadarTelegramBot(db=db, bot_token="test_token", chat_id="123456789")

    update = MagicMock()
    update.callback_query = MagicMock()
    update.callback_query.answer = AsyncMock()
    update.callback_query.data = f"chk:{inc_id}"
    update.callback_query.message.chat_id = 123456789

    context = MagicMock()
    context.bot.send_message = AsyncMock()

    await bot.button_callback(update, context)

    update.callback_query.answer.assert_called_once()
    context.bot.send_message.assert_called_once()
    sent_text = context.bot.send_message.call_args[1]["text"]
    assert "Vyper Reentrancy Hack" in sent_text
    assert "Auditor Checklist" in sent_text

    await db.close()


@pytest.mark.asyncio
async def test_bot_search_command():
    db = Database(":memory:")
    await db.initialize()

    await db.create_incident(
        title="Furucombo Cascading Trust Exploit",
        protocol="Furucombo",
        chain=["Ethereum"],
        attack_type=["ARBITRARY_EXECUTION"],
        estimated_loss_usd=14_000_000.0,
        severity="CRITICAL",
        status="active",
    )

    bot = RadarTelegramBot(db=db, bot_token="test_token", chat_id="123456789")

    # 1. Search with results
    update = make_mock_update(chat_id=123456789, message_text="/search furucombo")
    ctx = MagicMock()
    ctx.args = ["furucombo"]

    await bot.search_command(update, ctx)
    assert update.message.reply_text.call_count >= 2
    # Verify match text
    second_call_text = update.message.reply_text.call_args_list[1][0][0]
    assert "Furucombo" in second_call_text
    assert "$14,000,000" in second_call_text

    # 2. Search empty
    update_empty = make_mock_update(chat_id=123456789, message_text="/search nonexistent")
    ctx_empty = MagicMock()
    ctx_empty.args = ["nonexistent"]

    await bot.search_command(update_empty, ctx_empty)
    empty_call_text = update_empty.message.reply_text.call_args[0][0]
    assert "No incident records found" in empty_call_text

    # 3. Test /incident command
    update_inc = make_mock_update(chat_id=123456789, message_text="/incident 1")
    ctx_inc = MagicMock()
    ctx_inc.args = ["1"]
    await bot.incident_command(update_inc, ctx_inc)
    inc_call_text = update_inc.message.reply_text.call_args[0][0]
    assert "Incident #1" in inc_call_text
    assert "Furucombo" in inc_call_text

    await db.close()

