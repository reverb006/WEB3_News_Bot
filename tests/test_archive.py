"""
Unit tests for the Dual Knowledge Archive system (archive_security.md & archive_news.md).
"""

from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from app.database.db import Database
from app.models.schemas import SourceConfig, SourceType
from app.processing.archive import (
    ArchiveManager,
    is_security_item,
    format_security_entry,
    format_news_entry,
)


@pytest.fixture
def temp_reports_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


def test_is_security_item():
    sec_item = {
        "category": "CRITICAL_SECURITY",
        "severity": "CRITICAL",
        "estimated_loss_usd": 10_000_000,
        "security_relevance": 95,
    }
    assert is_security_item(sec_item) is True

    research_item = {
        "category": "SECURITY_RESEARCH",
        "severity": "MEDIUM",
        "security_relevance": 70,
    }
    assert is_security_item(research_item) is True

    news_item = {
        "category": "MAJOR_WEB3_NEWS",
        "severity": "LOW",
        "security_relevance": 10,
        "estimated_loss_usd": 0,
    }
    assert is_security_item(news_item) is False

    protocol_item = {
        "category": "PROTOCOL_UPDATE",
        "protocol": "Ethereum",
        "security_relevance": 20,
    }
    assert is_security_item(protocol_item) is False


def test_format_entries():
    sec_article = {
        "title": "Curve Finance Exploited",
        "url": "https://example.com/curve",
        "published_at": "2026-09-23T10:00:00Z",
        "severity": "CRITICAL",
        "protocol": "Curve Finance",
        "estimated_loss_usd": 61_000_000.0,
        "priority_score": 95,
        "source_name": "PeckShield",
        "summary": "Compiler reentrancy vulnerability in vyper pool.",
        "attack_type": ["REENTRANCY"],
        "chain": ["Ethereum"],
    }
    sec_text = format_security_entry(sec_article)
    assert "### Curve Finance Exploited" in sec_text
    assert "Curve Finance" in sec_text
    assert "$61,000,000.00" in sec_text
    assert "REENTRANCY" in sec_text
    assert "🚨 CRITICAL" in sec_text

    news_article = {
        "title": "Ethereum Completes Pectra Upgrade",
        "url": "https://example.com/pectra",
        "published_at": "2026-09-23T10:00:00Z",
        "category": "PROTOCOL_UPDATE",
        "priority_score": 30,
        "source_name": "CoinDesk",
        "summary": "Successful fork activation on mainnet.",
    }
    news_text = format_news_entry(news_article)
    assert "### Ethereum Completes Pectra Upgrade" in news_text
    assert "⚡ PROTOCOL UPDATE" in news_text
    assert "CoinDesk" in news_text


def test_archive_incremental_and_deduplication(temp_reports_dir):
    mgr = ArchiveManager(reports_dir=temp_reports_dir)

    sec_article = {
        "title": "Test Exploit",
        "url": "https://example.com/test1",
        "category": "CRITICAL_SECURITY",
        "severity": "CRITICAL",
        "priority_score": 90,
    }

    # First append should succeed
    res1 = mgr.archive_article(sec_article)
    assert res1 is True
    assert mgr.security_path.exists()
    content = mgr.security_path.read_text(encoding="utf-8")
    assert "Test Exploit" in content

    # Second append of exact same article must be skipped (deduplication)
    res2 = mgr.archive_article(sec_article)
    assert res2 is False


@pytest.mark.asyncio
async def test_backfill_archives(temp_reports_dir):
    db = Database(":memory:")
    await db.initialize()

    src = SourceConfig(
        name="PeckShield",
        url="http://p.com",
        source_type=SourceType.SECURITY_COMPANY,
        collector_type="rss",
    )
    src_id = await db.upsert_source(src)

    # Insert 1 security article
    await db.conn.execute(
        """
        INSERT INTO articles (url, url_hash, title, source_id, source_type, category, severity,
                              priority_score, estimated_loss_usd, classified_at, first_seen_at)
        VALUES ('http://sec.com', 'h1', 'Critical Protocol Hack', ?, 'SECURITY_COMPANY',
                'CRITICAL_SECURITY', 'CRITICAL', 90, 5000000.0, datetime('now'), datetime('now'))
        """,
        (src_id,),
    )
    # Insert 1 news article
    await db.conn.execute(
        """
        INSERT INTO articles (url, url_hash, title, source_id, source_type, category, severity,
                              priority_score, classified_at, first_seen_at)
        VALUES ('http://news.com', 'h2', 'Major Regulatory Framework Passed', ?, 'NEWS_MEDIA',
                'REGULATION', 'LOW', 25, datetime('now'), datetime('now'))
        """,
        (src_id,),
    )
    await db.conn.commit()

    mgr = ArchiveManager(reports_dir=temp_reports_dir)
    summary = await mgr.backfill_archives(db)

    assert summary["security_count"] == 1
    assert summary["news_count"] == 1
    assert summary["total"] == 2

    sec_content = mgr.security_path.read_text(encoding="utf-8")
    assert "Critical Protocol Hack" in sec_content
    assert "$5,000,000.00" in sec_content

    news_content = mgr.news_path.read_text(encoding="utf-8")
    assert "Major Regulatory Framework Passed" in news_content

    await db.close()
