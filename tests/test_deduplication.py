"""
Tests for title similarity, fuzzy deduplication, and incident merging logic.
"""

import pytest
from app.models.schemas import Classification, Category, Severity, AttackType, IncidentStatus
from app.processing.deduplication import (
    normalize_title,
    compute_title_similarity,
    are_articles_related,
    IncidentManager,
)
from app.database.db import Database


class TestTitleSimilarity:
    """Test title cleaning and similarity scoring."""

    def test_normalize_title(self):
        raw = "[PeckShieldAlert] BREAKING: Curve Finance Exploit -- $60M Loss!"
        cleaned = normalize_title(raw)
        assert cleaned == "curve finance exploit 60m loss"

    def test_similar_headlines_match(self):
        title1 = "Curve Finance pools drained in $60 million exploit linked to Vyper bug"
        title2 = "Curve Finance exploited for $61 million in compiler reentrancy attack"
        sim = compute_title_similarity(title1, title2)
        assert sim >= 0.50

    def test_identical_titles(self):
        title = "Prisma Finance Exploit Post-Mortem"
        assert compute_title_similarity(title, title) == 1.0

    def test_unrelated_headlines_differ(self):
        title1 = "Ethereum Dencun Upgrade Goes Live on Mainnet"
        title2 = "Curve Finance Exploited for $60M in Reentrancy Attack"
        sim = compute_title_similarity(title1, title2)
        assert sim <= 0.25

    def test_protocol_boost(self):
        # Even with slightly different wording, matching protocol allows connection
        title1 = "Security incident in lending pool"
        title2 = "Protocol drained of funds"
        # Without protocol
        assert are_articles_related(title1, title2) is False
        # With matching protocol
        assert are_articles_related(title1, title2, protocol1="Euler", protocol2="Euler") is False

        # When there are overlapping key terms and same protocol:
        t1 = "Euler Finance lending pool exploited"
        t2 = "Euler protocol drained in flash loan attack"
        assert are_articles_related(t1, t2, protocol1="Euler Finance", protocol2="Euler Finance") is True


@pytest.mark.asyncio
class TestIncidentMerging:
    """Test Incident creation, merging, and duplicate alert suppression."""

    def _make_class(self, **kwargs):
        defaults = {
            "title": "Curve Finance Exploited",
            "summary": "Vyper bug caused reentrancy",
            "category": Category.CRITICAL_SECURITY,
            "severity": Severity.CRITICAL,
            "security_relevance": 95,
            "confidence": 90,
            "protocol": "Curve Finance",
            "attack_type": [AttackType.REENTRANCY],
            "estimated_loss_usd": 60_000_000.0,
            "should_alert": True,
        }
        defaults.update(kwargs)
        return Classification(**defaults)

    async def test_multi_source_merging_into_single_incident(self, tmp_path):
        db = Database(tmp_path / "test_dedup.db")
        await db.initialize()

        # Add two sources
        c1 = await db.conn.execute("INSERT INTO sources (name, url, source_type) VALUES ('PeckShield', 'http://p.com', 'SECURITY_COMPANY')")
        src_peckshield = c1.lastrowid

        c2 = await db.conn.execute("INSERT INTO sources (name, url, source_type) VALUES ('CoinDesk', 'http://c.com', 'NEWS_MEDIA')")
        src_coindesk = c2.lastrowid

        # Insert article 1 from PeckShield
        art1 = await db.conn.execute(
            """
            INSERT INTO articles (url, url_hash, title, source_id, source_type, first_seen_at)
            VALUES ('http://p.com/1', 'hash1', 'Curve Finance pools drained in $60 million exploit linked to Vyper bug', ?, 'SECURITY_COMPANY', datetime('now'))
            """,
            (src_peckshield,),
        )
        art1_id = art1.lastrowid

        # Insert article 2 from CoinDesk (same event, different headline)
        art2 = await db.conn.execute(
            """
            INSERT INTO articles (url, url_hash, title, source_id, source_type, first_seen_at)
            VALUES ('http://c.com/2', 'hash2', 'Curve Finance exploited for $61 million in compiler reentrancy attack', ?, 'NEWS_MEDIA', datetime('now'))
            """,
            (src_coindesk,),
        )
        art2_id = art2.lastrowid
        await db.conn.commit()

        mgr = IncidentManager()

        # Process article 1
        class1 = self._make_class(estimated_loss_usd=60_000_000.0)
        inc_id1, is_new1 = await mgr.process_and_link(db, art1_id, "Curve Finance pools drained in $60 million exploit linked to Vyper bug", class1)

        assert is_new1 is True
        assert inc_id1 > 0

        # Verify article 1 is linked
        inc = await db.get_incident(inc_id1)
        assert inc["article_count"] == 1
        assert inc["protocol"] == "Curve Finance"
        assert inc["estimated_loss_usd"] == 60_000_000.0

        # Alert should fire for the first report
        should_alert1 = await mgr.should_dispatch_alert(db, inc_id1, priority_score=95, should_alert=True)
        assert should_alert1 is True

        # Simulate alert sent
        await db.record_alert(article_id=art1_id, alert_type="TELEGRAM", status="sent")

        # Now Process article 2 (CoinDesk reporting the exact same hack with higher loss $61M)
        class2 = self._make_class(estimated_loss_usd=61_000_000.0)
        inc_id2, is_new2 = await mgr.process_and_link(db, art2_id, "Curve Finance exploited for $61 million in compiler reentrancy attack", class2)

        # Article 2 MUST merge into Incident 1!
        assert is_new2 is False
        assert inc_id2 == inc_id1

        # Incident 1 should now have 2 articles and updated loss
        updated_inc = await db.get_incident(inc_id1)
        assert updated_inc["article_count"] == 2
        assert updated_inc["estimated_loss_usd"] == 61_000_000.0

        # Duplicate alert check: Article 2 must NOT trigger a second Telegram alert!
        should_alert2 = await mgr.should_dispatch_alert(db, inc_id2, priority_score=95, should_alert=True)
        assert should_alert2 is False, "Duplicate alert should be suppressed because incident was already alerted!"

        # Freshness filter check:
        # 1. Fresh article within 2 hours -> should alert
        from datetime import datetime, timezone, timedelta
        fresh_time = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        assert mgr.is_article_fresh(fresh_time, max_age_hours=48) is True

        # 2. Historical article from 2021 -> should NOT alert
        historical_time = "2021-08-10T12:00:00Z"
        assert mgr.is_article_fresh(historical_time, max_age_hours=48) is False

        # 3. New incident with historical date -> should_dispatch_alert returns False
        inc3 = await db.create_incident(title="Historical PolyNetwork Hack", status="active")
        should_alert_old = await mgr.should_dispatch_alert(
            db, inc3, priority_score=95, should_alert=True, published_at=historical_time
        )
        assert should_alert_old is False, "Historical article must be suppressed from real-time alert!"

        # 4. New incident with fresh date -> should_dispatch_alert returns True
        inc4 = await db.create_incident(title="Brand New 0-day Exploit", status="active")
        should_alert_fresh = await mgr.should_dispatch_alert(
            db, inc4, priority_score=95, should_alert=True, published_at=fresh_time
        )
        assert should_alert_fresh is True, "Fresh critical exploit must trigger real-time alert!"

        await db.close()
