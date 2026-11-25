"""
Tests for Daily Security Digest generator, markdown reports, and Telegram formatting.
"""

import pytest
from datetime import datetime, timezone
from app.models.schemas import DailyDigest, Category, Severity
from app.digest.daily import DailyDigestGenerator
from app.database.db import Database


@pytest.fixture
def sample_digest_data() -> DailyDigest:
    return DailyDigest(
        digest_date="2026-09-22",
        total_articles=15,
        total_incidents=2,
        total_loss_usd=60_000_000.0,
        critical_exploits=[
            {
                "id": 101,
                "title": "Curve Finance Exploited for $60M",
                "url": "https://example.com/curve",
                "source_name": "PeckShield",
                "protocol": "Curve Finance",
                "priority_score": 95,
                "estimated_loss_usd": 60_000_000.0,
                "summary": "Reentrancy lock bug in Vyper compiler.",
            }
        ],
        bug_bounties=[
            {
                "id": 102,
                "title": "Immunefi Sky Remote Code Execution Bugfix Review",
                "url": "https://example.com/sky-bugfix",
                "source_name": "Immunefi",
                "priority_score": 75,
                "summary": "Critical RCE disclosed and patched.",
            }
        ],
        security_research=[
            {
                "id": 103,
                "title": "Building secure Uniswap v4 hooks",
                "url": "https://example.com/uni-hooks",
                "source_name": "Trail of Bits",
                "priority_score": 44,
                "summary": "Best practices for Uniswap v4 hook security.",
            }
        ],
        protocol_updates=[
            {
                "id": 104,
                "title": "Ethereum Core Devs Call #180: Pectra Upgrade Specs",
                "url": "https://example.com/pectra",
                "source_name": "Ethereum Foundation",
                "priority_score": 40,
                "summary": "Pectra hard fork specifications confirmed.",
            }
        ],
        top_must_read=[
            {
                "id": 101,
                "title": "Curve Finance Exploited for $60M",
                "url": "https://example.com/curve",
                "source_name": "PeckShield",
                "category": "CRITICAL_SECURITY",
                "priority_score": 95,
            },
            {
                "id": 102,
                "title": "Immunefi Sky Remote Code Execution Bugfix Review",
                "url": "https://example.com/sky-bugfix",
                "source_name": "Immunefi",
                "category": "BUG_BOUNTY",
                "priority_score": 75,
            },
        ],
    )


class TestDailyDigestGenerator:
    """Test markdown report rendering and telegram message generation."""

    def test_markdown_digest_rendering(self, sample_digest_data):
        generator = DailyDigestGenerator()
        md = generator.generate_markdown_digest(sample_digest_data)

        assert "# 🛡️ Web3 Security Radar — Daily Intelligence Digest" in md
        assert "**Date:** `2026-09-22`" in md
        assert "## 📊 Executive Snapshot" in md
        assert "$60,000,000.00" in md
        assert "## 🚨 1. Critical Exploits & Losses" in md
        assert "[Curve Finance Exploited for $60M](https://example.com/curve)" in md
        assert "## 🐞 2. Bug Bounty Programs & Post-Mortem Disclosures" in md
        assert "Immunefi Sky Remote Code Execution Bugfix Review" in md
        assert "## 🔬 3. Security Research, Tooling & Audit Methodology" in md
        assert "Building secure Uniswap v4 hooks" in md
        assert "## ⚡ 4. Protocol Updates, EIPs & Client Releases" in md
        assert "Ethereum Core Devs Call #180" in md
        assert "## 🏆 5. Top 5 Must-Read Items" in md

    def test_telegram_digest_formatting(self, sample_digest_data):
        generator = DailyDigestGenerator()
        messages = generator.format_telegram_digest(sample_digest_data)

        assert len(messages) >= 1
        msg = messages[0]
        assert "WEB3 SECURITY RADAR — DAILY DIGEST" in msg
        assert "2026-09-22" in msg
        assert "$60,000,000" in msg
        assert "CRITICAL EXPLOITS &amp; LOSSES:" in msg
        assert "BUG BOUNTIES &amp; DISCLOSURES:" in msg
        assert "#CurveFinance" in msg
        assert "reports/digest_2026-09-22.md" in msg

    def test_save_digest_report_file(self, tmp_path, sample_digest_data, monkeypatch):
        import app.digest.daily as daily_module
        monkeypatch.setattr(daily_module, "REPORTS_DIR", tmp_path)

        generator = DailyDigestGenerator()
        md = generator.generate_markdown_digest(sample_digest_data)
        file_path = generator.save_digest_report("2026-09-22", md)

        assert file_path.exists()
        assert file_path.name == "digest_2026-09-22.md"
        assert file_path.read_text(encoding="utf-8") == md


@pytest.mark.asyncio
class TestDailyDigestDatabase:
    """Test database recording and querying of daily digests."""

    async def test_save_and_get_digest(self, tmp_path):
        db = Database(tmp_path / "test_digest.db")
        await db.initialize()

        assert await db.has_digest_been_sent("2026-09-22") is False

        await db.save_digest(
            digest_date="2026-09-22",
            content="# Sample Digest Content",
            article_count=10,
            incident_count=1,
            status="sent",
        )

        assert await db.has_digest_been_sent("2026-09-22") is True

        digest_rec = await db.get_digest("2026-09-22")
        assert digest_rec is not None
        assert digest_rec["digest_date"] == "2026-09-22"
        assert digest_rec["article_count"] == 10
        assert digest_rec["incident_count"] == 1
        assert digest_rec["content"] == "# Sample Digest Content"

        await db.close()

    async def test_digest_compilation_with_db(self, tmp_path):
        db = Database(tmp_path / "test_compile.db")
        await db.initialize()

        src_id = await db.conn.execute(
            """
            INSERT INTO sources (name, url, source_type, reliability_score, is_active)
            VALUES ('Trail of Bits', 'https://example.com/rss', 'SECURITY_COMPANY', 95, 1)
            """
        )
        await db.conn.commit()

        # Insert classified article
        await db.conn.execute(
            """
            INSERT INTO articles (
                url, url_hash, title, content, summary, published_at, first_seen_at,
                source_id, category, severity, security_relevance, confidence,
                priority_score, classified_at
            ) VALUES (
                'https://example.com/post1', 'hash1', 'Testing Handbook Chapter', 'Body',
                'Summary of testing handbook', '2026-09-22T00:00:00', '2026-09-22T01:00:00',
                1, 'SECURITY_RESEARCH', 'LOW', 80, 90, 43, '2026-09-22T01:05:00'
            )
            """
        )
        await db.conn.commit()

        generator = DailyDigestGenerator()
        digest = await generator.compile_digest(db, target_date="2026-09-22")

        assert digest.digest_date == "2026-09-22"
        assert digest.total_articles == 1
        assert len(digest.security_research) == 1
        assert digest.top_must_read[0]["title"] == "Testing Handbook Chapter"

        await db.close()
