"""
Tests for the database module.

These tests verify:
  - Database initialization creates all tables
  - Source CRUD operations
  - Article insertion and duplicate detection
  - Classification updates
  - Query methods

Each test uses a fresh in-memory SQLite database (no file created).
"""

import asyncio
import json
import pytest
import pytest_asyncio
from datetime import datetime, timezone

from app.database.db import Database
from app.models.schemas import (
    RawArticle, Classification, SourceConfig,
    SourceType, Category, Severity, IncidentStatus, AttackType,
)


@pytest_asyncio.fixture
async def db():
    """Create a fresh in-memory database for each test."""
    database = Database(":memory:")
    await database.initialize()
    yield database
    await database.close()


@pytest_asyncio.fixture
async def source_id(db):
    """Insert a test source and return its ID."""
    source = SourceConfig(
        name="Test Source",
        url="https://example.com/feed",
        source_type=SourceType.SECURITY_COMPANY,
        collector_type="rss",
        reliability_score=75,
    )
    return await db.upsert_source(source)


@pytest.fixture
def sample_article():
    """A minimal RawArticle for testing."""
    return RawArticle(
        url="https://example.com/article-1",
        title="Test Exploit Found in Protocol XYZ",
        content="A reentrancy vulnerability was discovered in Protocol XYZ...",
        published_at=datetime(2026, 9, 22, 12, 0, 0, tzinfo=timezone.utc),
        source_name="Test Source",
        source_type=SourceType.SECURITY_COMPANY,
        source_reliability=75,
    )


@pytest.fixture
def sample_classification():
    """A minimal Classification result."""
    return Classification(
        title="Reentrancy Exploit in Protocol XYZ",
        summary="A reentrancy vulnerability in Protocol XYZ was exploited for $2M.",
        category=Category.CRITICAL_SECURITY,
        severity=Severity.CRITICAL,
        security_relevance=95,
        confidence=85,
        estimated_loss_usd=2_000_000.0,
        chain=["Ethereum"],
        protocol="Protocol XYZ",
        attack_type=[AttackType.REENTRANCY],
        status=IncidentStatus.ACTIVE,
        source_type=SourceType.SECURITY_COMPANY,
        should_alert=True,
    )


# ============================================================
# Database initialization
# ============================================================

@pytest.mark.asyncio
async def test_db_initializes(db):
    """Database should create all tables without error."""
    # Check that the tables exist by querying them
    cursor = await db.conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
    tables = [row[0] for row in await cursor.fetchall()]

    assert "sources" in tables
    assert "articles" in tables
    assert "incidents" in tables
    assert "alerts" in tables
    assert "digests" in tables


@pytest.mark.asyncio
async def test_db_wal_mode(db):
    """In-memory DB can't use WAL (falls back to 'memory'). Real file DB would be WAL."""
    cursor = await db.conn.execute("PRAGMA journal_mode")
    row = await cursor.fetchone()
    # In-memory databases always use 'memory' journal mode — WAL only works on disk.
    # This test just verifies the pragma doesn't crash; WAL is tested implicitly
    # when running the real app with a file-based database.
    assert row[0] in ("wal", "memory")


# ============================================================
# Source operations
# ============================================================

@pytest.mark.asyncio
async def test_upsert_source(db):
    """Upserting a source should create it and return its ID."""
    source = SourceConfig(
        name="Trail of Bits",
        url="https://blog.trailofbits.com/feed/",
        source_type=SourceType.SECURITY_COMPANY,
        collector_type="rss",
        reliability_score=85,
    )
    source_id = await db.upsert_source(source)
    assert source_id > 0

    # Upserting again should return the same ID (not create a duplicate)
    source_id_2 = await db.upsert_source(source)
    assert source_id_2 == source_id


@pytest.mark.asyncio
async def test_get_source_id(db, source_id):
    """Should find a source by name."""
    found = await db.get_source_id("Test Source")
    assert found == source_id

    # Non-existent source returns None
    not_found = await db.get_source_id("Nonexistent")
    assert not_found is None


# ============================================================
# Article operations
# ============================================================

@pytest.mark.asyncio
async def test_insert_article(db, source_id, sample_article):
    """Inserting an article should return a valid ID."""
    article_id = await db.insert_article(sample_article, source_id)
    assert article_id > 0


@pytest.mark.asyncio
async def test_article_exists(db, source_id, sample_article):
    """article_exists should return True for stored URLs."""
    # Before insertion
    assert not await db.article_exists(sample_article.url)

    # After insertion
    await db.insert_article(sample_article, source_id)
    assert await db.article_exists(sample_article.url)

    # Different URL should not exist
    assert not await db.article_exists("https://example.com/other-article")


@pytest.mark.asyncio
async def test_duplicate_url_rejected(db, source_id, sample_article):
    """Inserting the same URL twice should raise an error."""
    await db.insert_article(sample_article, source_id)

    with pytest.raises(Exception):  # sqlite3.IntegrityError
        await db.insert_article(sample_article, source_id)


@pytest.mark.asyncio
async def test_update_classification(db, source_id, sample_article, sample_classification):
    """Classification update should store all fields."""
    article_id = await db.insert_article(sample_article, source_id)
    await db.update_article_classification(
        article_id, sample_classification, priority_score=85, raw_response='{"test": true}'
    )

    # Verify the update
    cursor = await db.conn.execute(
        "SELECT category, severity, security_relevance, estimated_loss_usd, "
        "chain, protocol, attack_type, should_alert, priority_score "
        "FROM articles WHERE id = ?",
        (article_id,),
    )
    row = await cursor.fetchone()

    assert row[0] == "CRITICAL_SECURITY"
    assert row[1] == "CRITICAL"
    assert row[2] == 95
    assert row[3] == 2_000_000.0
    assert json.loads(row[4]) == ["Ethereum"]
    assert row[5] == "Protocol XYZ"
    assert json.loads(row[6]) == ["REENTRANCY"]
    assert row[7] == 1  # should_alert = True
    assert row[8] == 85


@pytest.mark.asyncio
async def test_get_unclassified_articles(db, source_id, sample_article):
    """Should return only articles without classifications."""
    article_id = await db.insert_article(sample_article, source_id)

    # Before classification
    unclassified = await db.get_unclassified_articles()
    assert len(unclassified) == 1
    assert unclassified[0]["id"] == article_id

    # After classification
    classification = Classification(
        title="Test",
        summary="Test summary",
        category=Category.LOW_VALUE,
        severity=Severity.NONE,
        security_relevance=10,
        confidence=50,
    )
    await db.update_article_classification(article_id, classification, priority_score=5)

    unclassified = await db.get_unclassified_articles()
    assert len(unclassified) == 0


@pytest.mark.asyncio
async def test_article_count(db, source_id, sample_article):
    """Article count should track insertions."""
    assert await db.get_article_count() == 0

    await db.insert_article(sample_article, source_id)
    assert await db.get_article_count() == 1
