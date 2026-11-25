"""
Database module — SQLite connection, schema creation, and CRUD operations.

Architecture decisions:
  - Uses aiosqlite for async access (doesn't block the event loop)
  - Schema is created via raw SQL (no ORM overhead for a personal tool)
  - URL hash (SHA-256) enables fast duplicate lookups
  - JSON arrays stored as TEXT (SQLite has no native array type)
  - All timestamps stored as ISO-8601 strings (SQLite best practice)
  - WAL mode enabled for better concurrent read/write performance

The `Database` class is the ONLY place that touches SQLite directly.
Everything else in the app works with Pydantic models.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import aiosqlite

from app.models.schemas import RawArticle, Classification, ClassifiedArticle, SourceConfig

logger = logging.getLogger(__name__)


# ============================================================
# Schema DDL — the SQL that creates all tables
# ============================================================

SCHEMA_SQL = """
-- Sources we collect from
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    url TEXT NOT NULL,
    source_type TEXT NOT NULL,
    reliability_score INTEGER NOT NULL DEFAULT 50,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    last_fetched_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Every collected item
CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    url_hash TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    content TEXT,
    summary TEXT,
    published_at TEXT,
    first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
    source_id INTEGER NOT NULL REFERENCES sources(id),
    -- Classification fields (filled by Gemini)
    category TEXT,
    severity TEXT,
    security_relevance INTEGER,
    confidence INTEGER,
    estimated_loss_usd REAL,
    chain TEXT,
    protocol TEXT,
    attack_type TEXT,
    status TEXT,
    source_type TEXT,
    should_alert BOOLEAN DEFAULT 0,
    -- Priority
    priority_score INTEGER,
    -- Relationships
    incident_id INTEGER REFERENCES incidents(id),
    duplicate_of INTEGER REFERENCES articles(id),
    -- Raw AI response for debugging
    gemini_raw_response TEXT,
    classified_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Merged incident records (one per real-world event)
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    protocol TEXT,
    chain TEXT,
    attack_type TEXT,
    estimated_loss_usd REAL,
    severity TEXT,
    status TEXT,
    first_seen_at TEXT NOT NULL,
    last_updated_at TEXT NOT NULL,
    article_count INTEGER NOT NULL DEFAULT 1,
    deep_analysis TEXT,
    analyzed_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Alert tracking
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id INTEGER NOT NULL REFERENCES articles(id),
    incident_id INTEGER REFERENCES incidents(id),
    alert_type TEXT NOT NULL,
    telegram_message_id INTEGER,
    sent_at TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Daily digest tracking
CREATE TABLE IF NOT EXISTS digests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    digest_date TEXT NOT NULL UNIQUE,
    content TEXT NOT NULL,
    article_count INTEGER NOT NULL,
    incident_count INTEGER NOT NULL,
    sent_at TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Custom watchlist for protocols and vulnerability keywords
CREATE TABLE IF NOT EXISTS watchlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    keyword TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Indexes for fast lookups
CREATE INDEX IF NOT EXISTS idx_articles_url_hash ON articles(url_hash);
CREATE INDEX IF NOT EXISTS idx_articles_published ON articles(published_at);
CREATE INDEX IF NOT EXISTS idx_articles_category ON articles(category);
CREATE INDEX IF NOT EXISTS idx_articles_priority ON articles(priority_score);
CREATE INDEX IF NOT EXISTS idx_articles_incident ON articles(incident_id);
CREATE INDEX IF NOT EXISTS idx_articles_first_seen ON articles(first_seen_at);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_first_seen ON incidents(first_seen_at);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_watchlist_keyword ON watchlist(keyword);
"""


def _url_hash(url: str) -> str:
    """Create a SHA-256 hash of a URL for fast duplicate lookups."""
    return hashlib.sha256(url.strip().encode("utf-8")).hexdigest()


def _now_iso() -> str:
    """Current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


class Database:
    """
    Async SQLite database manager.

    Usage:
        db = Database("/path/to/radar.db")
        await db.initialize()        # Creates tables if needed
        await db.insert_article(...)  # Store data
        await db.close()             # Clean shutdown
    """

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self._connection: Optional[aiosqlite.Connection] = None

    async def initialize(self) -> None:
        """
        Open the database connection and create tables if they don't exist.

        Also enables WAL mode for better performance with concurrent reads.
        """
        # Ensure the directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._connection = await aiosqlite.connect(str(self.db_path))

        # Enable WAL mode — allows reads while writing
        await self._connection.execute("PRAGMA journal_mode=WAL")
        # Enable foreign key enforcement (off by default in SQLite!)
        await self._connection.execute("PRAGMA foreign_keys=ON")

        # Create all tables
        await self._connection.executescript(SCHEMA_SQL)
        await self._connection.commit()

        logger.info(f"Database initialized at {self.db_path}")

    async def close(self) -> None:
        """Close the database connection gracefully."""
        if self._connection:
            await self._connection.close()
            self._connection = None
            logger.info("Database connection closed")

    @property
    def conn(self) -> aiosqlite.Connection:
        """Get the active connection, or raise if not initialized."""
        if self._connection is None:
            raise RuntimeError("Database not initialized. Call await db.initialize() first.")
        return self._connection

    # ========================================================
    # Sources
    # ========================================================

    async def upsert_source(self, source: SourceConfig) -> int:
        """
        Insert or update a source configuration.

        Returns the source ID.
        """
        await self.conn.execute(
            """
            INSERT INTO sources (name, url, source_type, reliability_score, is_active)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                url = excluded.url,
                source_type = excluded.source_type,
                reliability_score = excluded.reliability_score,
                is_active = excluded.is_active
            """,
            (
                source.name,
                source.url,
                source.source_type.value,
                source.reliability_score,
                source.is_active,
            ),
        )
        await self.conn.commit()

        cursor = await self.conn.execute(
            "SELECT id FROM sources WHERE name = ?", (source.name,)
        )
        row = await cursor.fetchone()
        return row[0]

    async def get_source_id(self, source_name: str) -> Optional[int]:
        """Look up a source ID by name."""
        cursor = await self.conn.execute(
            "SELECT id FROM sources WHERE name = ?", (source_name,)
        )
        row = await cursor.fetchone()
        return row[0] if row else None

    async def update_source_fetch_status(
        self, source_name: str, error: Optional[str] = None
    ) -> None:
        """Record that we just fetched from a source (success or failure)."""
        await self.conn.execute(
            """
            UPDATE sources SET
                last_fetched_at = ?,
                last_error = ?
            WHERE name = ?
            """,
            (_now_iso(), error, source_name),
        )
        await self.conn.commit()

    # ========================================================
    # Articles
    # ========================================================

    async def article_exists(self, url: str) -> bool:
        """Check if we already have an article with this URL."""
        cursor = await self.conn.execute(
            "SELECT 1 FROM articles WHERE url_hash = ?", (_url_hash(url),)
        )
        return await cursor.fetchone() is not None

    async def insert_article(self, article: RawArticle, source_id: int) -> int:
        """
        Insert a new raw (unclassified) article.

        Returns the new article ID.
        Raises sqlite3.IntegrityError if the URL already exists (duplicate).
        """
        now = _now_iso()
        published = article.published_at.isoformat() if article.published_at else None

        cursor = await self.conn.execute(
            """
            INSERT INTO articles (
                url, url_hash, title, content, published_at,
                first_seen_at, source_id, source_type, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                article.url,
                _url_hash(article.url),
                article.title,
                article.content,
                published,
                now,
                source_id,
                article.source_type.value,
                now,
                now,
            ),
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def update_article_classification(
        self,
        article_id: int,
        classification: Classification,
        priority_score: int,
        raw_response: str = "",
    ) -> None:
        """Update an article with its Gemini classification results."""
        now = _now_iso()
        await self.conn.execute(
            """
            UPDATE articles SET
                summary = ?,
                category = ?,
                severity = ?,
                security_relevance = ?,
                confidence = ?,
                estimated_loss_usd = ?,
                chain = ?,
                protocol = ?,
                attack_type = ?,
                status = ?,
                should_alert = ?,
                priority_score = ?,
                gemini_raw_response = ?,
                classified_at = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                classification.summary,
                classification.category.value,
                classification.severity.value,
                classification.security_relevance,
                classification.confidence,
                classification.estimated_loss_usd,
                json.dumps(classification.chain),
                classification.protocol,
                json.dumps([at.value for at in classification.attack_type]),
                classification.status.value,
                classification.should_alert,
                priority_score,
                raw_response,
                now,
                now,
                article_id,
            ),
        )
        await self.conn.commit()

    async def get_unclassified_articles(self, limit: int = 50) -> list[dict]:
        """Get articles that haven't been classified yet."""
        cursor = await self.conn.execute(
            """
            SELECT a.id, a.url, a.title, a.content, a.published_at,
                   a.source_type, s.name as source_name, s.reliability_score
            FROM articles a
            JOIN sources s ON a.source_id = s.id
            WHERE a.classified_at IS NULL
            ORDER BY COALESCE(a.published_at, a.first_seen_at) ASC
            LIMIT ?
            """,
            (limit,),
        )
        columns = [desc[0] for desc in cursor.description]
        rows = await cursor.fetchall()
        return [dict(zip(columns, row)) for row in rows]

    async def get_recent_titles(self, hours: int = 72) -> list[tuple[int, str]]:
        """
        Get (id, title) pairs from the last N hours.
        Used by the deduplicator to check for fuzzy title matches.
        """
        cursor = await self.conn.execute(
            """
            SELECT id, title FROM articles
            WHERE first_seen_at >= datetime('now', ? || ' hours')
            ORDER BY first_seen_at DESC
            """,
            (f"-{hours}",),
        )
        return await cursor.fetchall()

    async def get_latest_classified_date(self) -> Optional[str]:
        """Get the most recent date string (YYYY-MM-DD) that contains classified articles."""
        cursor = await self.conn.execute(
            """
            SELECT MAX(date(first_seen_at))
            FROM articles
            WHERE classified_at IS NOT NULL
            """
        )
        row = await cursor.fetchone()
        return row[0] if row and row[0] else None

    async def get_articles_for_digest(self, date_str: Optional[str] = None) -> list[dict]:
        """
        Get all classified articles from a specific date for the digest.
        If date_str is None or 'latest', uses the latest available date with classifications.
        """
        if not date_str or date_str.lower() == "latest":
            latest = await self.get_latest_classified_date()
            if not latest:
                return []
            date_str = latest

        cursor = await self.conn.execute(
            """
            SELECT a.*, s.name as source_name
            FROM articles a
            JOIN sources s ON a.source_id = s.id
            WHERE date(a.first_seen_at) = ?
              AND a.classified_at IS NOT NULL
              AND a.category NOT IN ('IGNORE', 'LOW_VALUE', 'MARKET')
            ORDER BY a.priority_score DESC
            """,
            (date_str,),
        )
        columns = [desc[0] for desc in cursor.description]
        rows = await cursor.fetchall()
        return [dict(zip(columns, row)) for row in rows]


    async def get_article_count(self) -> int:
        """Total number of articles in the database."""
        cursor = await self.conn.execute("SELECT COUNT(*) FROM articles")
        row = await cursor.fetchone()
        return row[0]

    async def get_source_stats(self) -> list[dict]:
        """Get collection stats per source."""
        cursor = await self.conn.execute(
            """
            SELECT s.name, s.source_type, s.is_active,
                   s.last_fetched_at, s.last_error,
                   COUNT(a.id) as article_count
            FROM sources s
            LEFT JOIN articles a ON s.id = a.source_id
            GROUP BY s.id
            ORDER BY article_count DESC
            """
        )
        columns = [desc[0] for desc in cursor.description]
        rows = await cursor.fetchall()
        return [dict(zip(columns, row)) for row in rows]

    # ========================================================
    # Alerts
    # ========================================================

    async def has_alert_been_sent(self, article_id: int) -> bool:
        """Check if an alert has already been successfully sent for this article."""
        cursor = await self.conn.execute(
            "SELECT 1 FROM alerts WHERE article_id = ? AND status = 'sent'",
            (article_id,),
        )
        return await cursor.fetchone() is not None

    async def record_alert(
        self,
        article_id: int,
        alert_type: str = "TELEGRAM",
        telegram_message_id: Optional[int] = None,
        status: str = "sent",
        error: Optional[str] = None,
        incident_id: Optional[int] = None,
    ) -> int:
        """Record an alert dispatch attempt or success in the database."""
        now = _now_iso()
        cursor = await self.conn.execute(
            """
            INSERT INTO alerts (
                article_id, incident_id, alert_type, telegram_message_id,
                sent_at, status, error, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                article_id,
                incident_id,
                alert_type,
                telegram_message_id,
                now if status == "sent" else None,
                status,
                error,
                now,
            ),
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def get_unalerted_critical_articles(self, min_priority: int = 70) -> list[dict]:
        """Get classified articles that qualify for an alert but haven't been alerted yet."""
        cursor = await self.conn.execute(
            """
            SELECT a.*, s.name as source_name
            FROM articles a
            JOIN sources s ON a.source_id = s.id
            WHERE a.classified_at IS NOT NULL
              AND (a.priority_score >= ? OR a.should_alert = 1)
              AND NOT EXISTS (
                  SELECT 1 FROM alerts al
                  WHERE al.article_id = a.id AND al.status = 'sent'
              )
            ORDER BY a.priority_score DESC
            """,
            (min_priority,),
        )
        columns = [desc[0] for desc in cursor.description]
        rows = await cursor.fetchall()
        return [dict(zip(columns, row)) for row in rows]

    # ========================================================
    # Incidents & Merging
    # ========================================================

    async def create_incident(
        self,
        title: str,
        protocol: Optional[str] = None,
        chain: Optional[list] = None,
        attack_type: Optional[list] = None,
        estimated_loss_usd: Optional[float] = None,
        severity: Optional[str] = None,
        status: str = "active",
    ) -> int:
        """Create a new incident record."""
        now = _now_iso()
        chain_json = json.dumps(chain or [])
        attack_json = json.dumps(attack_type or [])
        cursor = await self.conn.execute(
            """
            INSERT INTO incidents (
                title, protocol, chain, attack_type, estimated_loss_usd,
                severity, status, first_seen_at, last_updated_at,
                article_count, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
            """,
            (
                title,
                protocol,
                chain_json,
                attack_json,
                estimated_loss_usd,
                severity,
                status,
                now,
                now,
                now,
            ),
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def update_incident(
        self,
        incident_id: int,
        estimated_loss_usd: Optional[float] = None,
        severity: Optional[str] = None,
    ) -> None:
        """Update an incident when a new corroborating article is linked."""
        now = _now_iso()
        if estimated_loss_usd is not None:
            await self.conn.execute(
                """
                UPDATE incidents SET
                    article_count = article_count + 1,
                    last_updated_at = ?,
                    estimated_loss_usd = MAX(COALESCE(estimated_loss_usd, 0), ?),
                    severity = COALESCE(?, severity)
                WHERE id = ?
                """,
                (now, estimated_loss_usd, severity, incident_id),
            )
        else:
            await self.conn.execute(
                """
                UPDATE incidents SET
                    article_count = article_count + 1,
                    last_updated_at = ?
                WHERE id = ?
                """,
                (now, incident_id),
            )
        await self.conn.commit()

    async def get_active_incidents(self, hours: int = 72) -> list[dict]:
        """Get all incidents updated within the last N hours."""
        cursor = await self.conn.execute(
            """
            SELECT * FROM incidents
            WHERE last_updated_at >= datetime('now', ? || ' hours')
            ORDER BY last_updated_at DESC
            """,
            (f"-{hours}",),
        )
        columns = [desc[0] for desc in cursor.description]
        rows = await cursor.fetchall()
        return [dict(zip(columns, row)) for row in rows]

    async def link_article_to_incident(
        self,
        article_id: int,
        incident_id: int,
        duplicate_of: Optional[int] = None,
    ) -> None:
        """Link an article to an incident and optionally set duplicate_of pointer."""
        await self.conn.execute(
            """
            UPDATE articles SET
                incident_id = ?,
                duplicate_of = ?
            WHERE id = ?
            """,
            (incident_id, duplicate_of, article_id),
        )
        await self.conn.commit()

    async def get_incident(self, incident_id: int) -> Optional[dict]:
        """Fetch a single incident by ID."""
        cursor = await self.conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        columns = [desc[0] for desc in cursor.description]
        return dict(zip(columns, row))

    async def get_incident_articles(self, incident_id: int) -> list[dict]:
        """Get all articles linked to a specific incident."""
        cursor = await self.conn.execute(
            """
            SELECT a.*, s.name as source_name
            FROM articles a
            JOIN sources s ON a.source_id = s.id
            WHERE a.incident_id = ?
            ORDER BY a.first_seen_at ASC
            """,
            (incident_id,),
        )
        columns = [desc[0] for desc in cursor.description]
        rows = await cursor.fetchall()
        return [dict(zip(columns, row)) for row in rows]

    async def has_incident_been_alerted(self, incident_id: int) -> bool:
        """Check if an alert has already been sent for any article in this incident."""
        cursor = await self.conn.execute(
            """
            SELECT 1 FROM alerts al
            JOIN articles a ON al.article_id = a.id
            WHERE a.incident_id = ? AND al.status = 'sent'
            """,
            (incident_id,),
        )
        return await cursor.fetchone() is not None

    async def save_incident_analysis(self, incident_id: int, analysis_text: str) -> None:
        """Store deep analysis case study and timestamp for an incident."""
        now = _now_iso()
        await self.conn.execute(
            """
            UPDATE incidents SET
                deep_analysis = ?,
                analyzed_at = ?
            WHERE id = ?
            """,
            (analysis_text, now, incident_id),
        )
        await self.conn.commit()

    # ========================================================
    # Daily Digests
    # ========================================================

    async def get_incidents_for_digest(self, date_str: Optional[str] = None) -> list[dict]:
        """
        Get all incidents first seen or updated on a specific date.
        If date_str is None or 'latest', uses the latest date with incidents.
        """
        if not date_str or date_str.lower() == "latest":
            cursor = await self.conn.execute(
                "SELECT MAX(date(last_updated_at)) FROM incidents"
            )
            row = await cursor.fetchone()
            if not row or not row[0]:
                return []
            date_str = row[0]

        cursor = await self.conn.execute(
            """
            SELECT * FROM incidents
            WHERE date(first_seen_at) = ? OR date(last_updated_at) = ?
            ORDER BY article_count DESC, id DESC
            """,
            (date_str, date_str),
        )
        columns = [desc[0] for desc in cursor.description]
        rows = await cursor.fetchall()
        return [dict(zip(columns, row)) for row in rows]

    async def save_digest(
        self,
        digest_date: str,
        content: str,
        article_count: int,
        incident_count: int,
        status: str = "sent",
    ) -> int:
        """Store or update a daily digest record."""
        now = _now_iso()
        cursor = await self.conn.execute(
            """
            INSERT INTO digests (digest_date, content, article_count, incident_count, sent_at, status)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(digest_date) DO UPDATE SET
                content = excluded.content,
                article_count = excluded.article_count,
                incident_count = excluded.incident_count,
                sent_at = excluded.sent_at,
                status = excluded.status
            """,
            (digest_date, content, article_count, incident_count, now, status),
        )
        await self.conn.commit()
        return cursor.lastrowid

    async def get_digest(self, digest_date: str) -> Optional[dict]:
        """Retrieve a stored daily digest record by date."""
        cursor = await self.conn.execute(
            "SELECT * FROM digests WHERE digest_date = ?", (digest_date,)
        )
        row = await cursor.fetchone()
        if not row:
            return None
        columns = [desc[0] for desc in cursor.description]
        return dict(zip(columns, row))

    async def has_digest_been_sent(self, digest_date: str) -> bool:
        """Check if a digest has already been sent for this date."""
        cursor = await self.conn.execute(
            "SELECT 1 FROM digests WHERE digest_date = ? AND status = 'sent'",
            (digest_date,),
        )
        return await cursor.fetchone() is not None

    # ========================================================
    # Watchlist
    # ========================================================

    async def add_watchlist_keyword(self, keyword: str) -> bool:
        """Add a keyword or protocol to the watchlist. Returns True if added, False if duplicate/empty."""
        clean = keyword.strip().lower()
        if not clean:
            return False
        try:
            await self.conn.execute(
                "INSERT INTO watchlist (keyword) VALUES (?)", (clean,)
            )
            await self.conn.commit()
            return True
        except Exception:
            return False

    async def remove_watchlist_keyword(self, keyword: str) -> bool:
        """Remove a keyword from the watchlist. Returns True if removed, False if not found."""
        clean = keyword.strip().lower()
        cursor = await self.conn.execute(
            "DELETE FROM watchlist WHERE keyword = ?", (clean,)
        )
        await self.conn.commit()
        return cursor.rowcount > 0

    async def get_watchlist_keywords(self) -> list[str]:
        """Return list of all watched keywords."""
        cursor = await self.conn.execute("SELECT keyword FROM watchlist ORDER BY keyword ASC")
        rows = await cursor.fetchall()
        return [row[0] for row in rows]

    async def check_watchlist_match(self, text: str) -> Optional[str]:
        """Check if any watched keyword appears in the given text."""
        if not text:
            return None
        text_lower = text.lower()
        keywords = await self.get_watchlist_keywords()
        for kw in keywords:
            if kw in text_lower:
                return kw
        return None

