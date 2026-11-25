"""
Tests for Pydantic schemas — validate data models and their validators.

These tests verify:
  - RawArticle rejects empty titles and invalid URLs
  - Classification model accepts valid data
  - Enums contain all expected values
  - SourceConfig has proper defaults
"""

import pytest
from datetime import datetime, timezone

from app.models.schemas import (
    RawArticle, Classification, SourceConfig,
    Category, Severity, AttackType, IncidentStatus, SourceType,
)


# ============================================================
# RawArticle validation
# ============================================================

class TestRawArticle:
    """Tests for the RawArticle model."""

    def test_valid_article(self):
        """Should accept a well-formed article."""
        article = RawArticle(
            url="https://example.com/article",
            title="Test Article",
            content="Some content here",
            source_name="Test Source",
            source_type=SourceType.NEWS_MEDIA,
        )
        assert article.title == "Test Article"
        assert article.url == "https://example.com/article"

    def test_rejects_empty_title(self):
        """Empty titles should be rejected — they're useless."""
        with pytest.raises(ValueError, match="empty"):
            RawArticle(
                url="https://example.com/article",
                title="",
                source_name="Test",
                source_type=SourceType.NEWS_MEDIA,
            )

    def test_rejects_whitespace_title(self):
        """Whitespace-only titles should also be rejected."""
        with pytest.raises(ValueError, match="empty"):
            RawArticle(
                url="https://example.com/article",
                title="   ",
                source_name="Test",
                source_type=SourceType.NEWS_MEDIA,
            )

    def test_rejects_invalid_url(self):
        """URLs must start with http:// or https://."""
        with pytest.raises(ValueError, match="http"):
            RawArticle(
                url="ftp://example.com/article",
                title="Test",
                source_name="Test",
                source_type=SourceType.NEWS_MEDIA,
            )

    def test_rejects_no_scheme_url(self):
        """URLs without a scheme should be rejected."""
        with pytest.raises(ValueError, match="http"):
            RawArticle(
                url="example.com/article",
                title="Test",
                source_name="Test",
                source_type=SourceType.NEWS_MEDIA,
            )

    def test_default_values(self):
        """Optional fields should have sensible defaults."""
        article = RawArticle(
            url="https://example.com/article",
            title="Test",
            source_name="Test",
            source_type=SourceType.NEWS_MEDIA,
        )
        assert article.content == ""
        assert article.published_at is None
        assert article.source_reliability == 50


# ============================================================
# Classification validation
# ============================================================

class TestClassification:
    """Tests for the Classification model (Gemini response schema)."""

    def test_valid_classification(self):
        """Should accept a fully specified classification."""
        c = Classification(
            title="Test Exploit",
            summary="A test exploit was found.",
            category=Category.CRITICAL_SECURITY,
            severity=Severity.CRITICAL,
            security_relevance=95,
            confidence=80,
            estimated_loss_usd=5_000_000.0,
            chain=["Ethereum"],
            protocol="TestProtocol",
            attack_type=[AttackType.REENTRANCY],
            status=IncidentStatus.ACTIVE,
            should_alert=True,
        )
        assert c.category == Category.CRITICAL_SECURITY
        assert c.estimated_loss_usd == 5_000_000.0

    def test_minimal_classification(self):
        """Should accept classification with only required fields."""
        c = Classification(
            title="Some news",
            summary="Not very important",
            category=Category.LOW_VALUE,
            severity=Severity.NONE,
            security_relevance=5,
            confidence=90,
        )
        assert c.estimated_loss_usd is None
        assert c.chain == []
        assert c.protocol == ""
        assert c.attack_type == []

    def test_relevance_bounds(self):
        """security_relevance must be 0-100."""
        with pytest.raises(ValueError):
            Classification(
                title="T", summary="S",
                category=Category.LOW_VALUE,
                severity=Severity.NONE,
                security_relevance=150,  # Too high
                confidence=50,
            )

    def test_confidence_bounds(self):
        """confidence must be 0-100."""
        with pytest.raises(ValueError):
            Classification(
                title="T", summary="S",
                category=Category.LOW_VALUE,
                severity=Severity.NONE,
                security_relevance=50,
                confidence=-10,  # Too low
            )


# ============================================================
# Enums
# ============================================================

class TestEnums:
    """Verify all expected enum values exist."""

    def test_categories(self):
        """All security categories should be defined."""
        expected = {
            "CRITICAL_SECURITY", "HIGH_SECURITY", "SECURITY_RESEARCH",
            "PROTOCOL_UPDATE", "MAJOR_WEB3_NEWS", "REGULATION",
            "MARKET", "LOW_VALUE", "IGNORE",
        }
        actual = {c.value for c in Category}
        assert expected == actual

    def test_attack_types(self):
        """All attack types should be defined."""
        expected = {
            "REENTRANCY", "ORACLE_MANIPULATION", "FLASH_LOAN",
            "ACCESS_CONTROL", "PRIVATE_KEY_COMPROMISE", "SIGNATURE_VALIDATION",
            "BRIDGE", "PROXY", "UPGRADEABILITY", "PRICE_MANIPULATION",
            "LOGIC_ERROR", "ARITHMETIC", "VALIDATION_BYPASS", "CROSS_CHAIN",
            "GOVERNANCE", "PHISHING", "RUGPULL", "UNKNOWN", "OTHER",
        }
        actual = {at.value for at in AttackType}
        assert expected == actual

    def test_source_types(self):
        """All source types should be defined."""
        assert SourceType.PRIMARY_SOURCE.value == "PRIMARY_SOURCE"
        assert SourceType.SECURITY_COMPANY.value == "SECURITY_COMPANY"
        assert SourceType.NEWS_MEDIA.value == "NEWS_MEDIA"
        assert SourceType.INCIDENT_DATABASE.value == "INCIDENT_DATABASE"


# ============================================================
# SourceConfig
# ============================================================

class TestSourceConfig:
    """Tests for source configuration model."""

    def test_defaults(self):
        """Should have reasonable defaults."""
        s = SourceConfig(
            name="Test",
            url="https://example.com/feed",
            source_type=SourceType.NEWS_MEDIA,
            collector_type="rss",
        )
        assert s.reliability_score == 50
        assert s.is_active is True
        assert s.max_items == 50

    def test_reliability_bounds(self):
        """reliability_score must be 0-100."""
        with pytest.raises(ValueError):
            SourceConfig(
                name="Test",
                url="https://example.com",
                source_type=SourceType.NEWS_MEDIA,
                collector_type="rss",
                reliability_score=200,
            )
