"""
Tests for Telegram alert formatting and dispatching logic.
"""

import json
import pytest
from unittest.mock import AsyncMock, patch

from app.alerts.telegram import format_alert_message, TelegramAlertManager
from app.database.db import Database


class TestAlertFormatting:
    """Test format_alert_message generates clean, escaped HTML."""

    def test_critical_alert_formatting(self):
        article = {
            "title": "Curve Finance <Exploited> for $60M",
            "url": "https://example.com/curve-hack",
            "category": "CRITICAL_SECURITY",
            "severity": "CRITICAL",
            "priority_score": 95,
            "protocol": "Curve Finance",
            "estimated_loss_usd": 60000000.0,
            "attack_type": json.dumps(["REENTRANCY", "COMPILER_BUG"]),
            "chain": json.dumps(["Ethereum", "Arbitrum"]),
            "summary": "Attacker exploited a reentrancy lock flaw in older Vyper compiler versions.",
            "source_name": "PeckShield & Co",
        }

        msg = format_alert_message(article)

        assert "CRITICAL WEB3 EXPLOIT DETECTED" in msg
        assert "Curve Finance &lt;Exploited&gt; for $60M" in msg  # HTML escaped
        assert "Protocol:</b> Curve Finance (#CurveFinance)" in msg
        assert "Estimated Loss:</b> $60,000,000.00" in msg
        assert "Attack Vector:</b> REENTRANCY, COMPILER_BUG" in msg
        assert "Chain:</b> Ethereum, Arbitrum" in msg
        assert "Severity:</b> CRITICAL | <b>Priority:</b> 95/100" in msg
        assert "PeckShield &amp; Co" in msg
        assert 'href="https://example.com/curve-hack"' in msg

    def test_high_alert_formatting(self):
        article = {
            "title": "Uniswap v4 Hook Access Control Bug",
            "url": "https://example.com/uniswap-bug",
            "category": "HIGH_SECURITY",
            "severity": "HIGH",
            "priority_score": 75,
            "protocol": "Uniswap",
            "estimated_loss_usd": None,
            "attack_type": '["ACCESS_CONTROL"]',
            "summary": "Access control issue in custom hook implementation.",
            "source_name": "Immunefi",
        }

        msg = format_alert_message(article)

        assert "HIGH-SEVERITY SECURITY ALERT" in msg
        assert "Uniswap (#Uniswap)" in msg
        assert "ACCESS_CONTROL" in msg
        assert "Estimated Loss" not in msg  # No loss mentioned

    def test_html_safety(self):
        article = {
            "title": '<script>alert("xss")</script>',
            "summary": "Vulnerability with <b>tags</b> & \"quotes\"",
            "source_name": "Test <Source>",
        }

        msg = format_alert_message(article)
        assert "<script>" not in msg
        assert "&lt;script&gt;" in msg
        assert "&amp;" in msg
        assert "&lt;Source&gt;" in msg


@pytest.mark.asyncio
class TestAlertManagerDatabaseIntegration:
    """Test database recording and deduplication in alert manager."""

    async def test_alert_recording_and_deduplication(self, tmp_path):
        db = Database(tmp_path / "test_alerts.db")
        await db.initialize()

        # Add a source and article
        cursor = await db.conn.execute(
            "INSERT INTO sources (name, url, source_type) VALUES ('PeckShield', 'http://a.com', 'SECURITY_COMPANY')"
        )
        source_id = cursor.lastrowid

        cursor = await db.conn.execute(
            """
            INSERT INTO articles (
                url, url_hash, title, source_id, source_type,
                category, severity, priority_score, should_alert, classified_at
            ) VALUES ('http://a.com/hack', 'hash1', 'Test Hack', ?, 'SECURITY_COMPANY',
                      'CRITICAL_SECURITY', 'CRITICAL', 90, 1, datetime('now'))
            """,
            (source_id,),
        )
        article_id = cursor.lastrowid
        await db.conn.commit()

        # Check unalerted
        unalerted = await db.get_unalerted_critical_articles(min_priority=70)
        assert len(unalerted) == 1
        assert unalerted[0]["id"] == article_id

        # Verify not yet alerted
        assert await db.has_alert_been_sent(article_id) is False

        # Record an alert
        alert_id = await db.record_alert(
            article_id=article_id,
            alert_type="TELEGRAM",
            telegram_message_id=12345,
            status="sent",
        )
        assert alert_id > 0

        # Verify now alerted
        assert await db.has_alert_been_sent(article_id) is True

        # Check unalerted query excludes it now
        unalerted_after = await db.get_unalerted_critical_articles(min_priority=70)
        assert len(unalerted_after) == 0

        await db.close()
