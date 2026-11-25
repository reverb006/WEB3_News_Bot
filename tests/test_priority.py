"""
Tests for the priority scoring algorithm.

Verifies that the scoring weights produce sensible results:
  - Critical exploits score high
  - Market news scores low
  - Source reliability affects score
  - Active attacks get a bonus
  - Financial loss scales the score
"""

import pytest

from app.models.schemas import (
    Classification, Category, Severity, IncidentStatus,
    AttackType, SourceType,
)
from app.processing.priority import (
    compute_priority, should_alert, should_deep_analyze,
    ALERT_THRESHOLD, DEEP_ANALYSIS_THRESHOLD,
)


def _make_classification(**kwargs) -> Classification:
    """Helper to build a Classification with sensible defaults."""
    defaults = {
        "title": "Test",
        "summary": "Test summary",
        "category": Category.LOW_VALUE,
        "severity": Severity.NONE,
        "security_relevance": 10,
        "confidence": 50,
    }
    defaults.update(kwargs)
    return Classification(**defaults)


class TestPriorityScoring:
    """Tests for compute_priority()."""

    def test_critical_exploit_scores_high(self):
        """A confirmed critical exploit should score very high."""
        c = _make_classification(
            category=Category.CRITICAL_SECURITY,
            severity=Severity.CRITICAL,
            security_relevance=95,
            estimated_loss_usd=50_000_000,
            status=IncidentStatus.ACTIVE,
        )
        score = compute_priority(c, source_reliability=85)
        # Should be: cat=40 + loss=15 + src=12 + rel=14 + active=10 = 91
        assert score >= 85, f"Critical exploit should score >=85, got {score}"

    def test_market_news_scores_low(self):
        """Market/price news should score near zero."""
        c = _make_classification(
            category=Category.MARKET,
            severity=Severity.NONE,
            security_relevance=5,
        )
        score = compute_priority(c, source_reliability=40)
        # Should be: cat=0 + loss=0 + src=6 + rel=0 + active=0 = 6
        assert score < 15, f"Market news should score <15, got {score}"

    def test_security_research_scores_medium(self):
        """Good security research should score medium-high."""
        c = _make_classification(
            category=Category.SECURITY_RESEARCH,
            severity=Severity.MEDIUM,
            security_relevance=70,
        )
        score = compute_priority(c, source_reliability=85)
        # Should be: cat=20 + loss=0 + src=12 + rel=10 = 42
        assert 30 <= score <= 55, f"Security research should score 30-55, got {score}"

    def test_source_reliability_matters(self):
        """Same article from a better source should score higher."""
        c = _make_classification(
            category=Category.HIGH_SECURITY,
            severity=Severity.HIGH,
            security_relevance=80,
        )
        score_high_rel = compute_priority(c, source_reliability=90)
        score_low_rel = compute_priority(c, source_reliability=30)

        assert score_high_rel > score_low_rel, (
            f"Higher reliability ({score_high_rel}) should beat lower ({score_low_rel})"
        )

    def test_active_attack_bonus(self):
        """Active attacks should score higher than contained ones."""
        base = dict(
            category=Category.HIGH_SECURITY,
            severity=Severity.HIGH,
            security_relevance=70,
        )
        active = _make_classification(status=IncidentStatus.ACTIVE, **base)
        contained = _make_classification(status=IncidentStatus.CONTAINED, **base)

        score_active = compute_priority(active, source_reliability=50)
        score_contained = compute_priority(contained, source_reliability=50)

        assert score_active > score_contained, (
            f"Active ({score_active}) should beat contained ({score_contained})"
        )
        assert score_active - score_contained == 10, "Active bonus should be exactly 10"

    def test_financial_loss_scaling(self):
        """Larger financial losses should produce higher scores."""
        base = dict(
            category=Category.CRITICAL_SECURITY,
            severity=Severity.CRITICAL,
            security_relevance=90,
        )
        loss_100m = _make_classification(estimated_loss_usd=100_000_000, **base)
        loss_1m = _make_classification(estimated_loss_usd=1_000_000, **base)
        loss_none = _make_classification(estimated_loss_usd=None, **base)

        s_100m = compute_priority(loss_100m, source_reliability=50)
        s_1m = compute_priority(loss_1m, source_reliability=50)
        s_none = compute_priority(loss_none, source_reliability=50)

        assert s_100m > s_1m > s_none, (
            f"$100M ({s_100m}) > $1M ({s_1m}) > None ({s_none})"
        )

    def test_score_clamped_to_100(self):
        """Score should never exceed 100 even with all maximums."""
        c = _make_classification(
            category=Category.CRITICAL_SECURITY,
            severity=Severity.CRITICAL,
            security_relevance=100,
            estimated_loss_usd=500_000_000,
            status=IncidentStatus.ACTIVE,
        )
        score = compute_priority(c, source_reliability=100)
        assert score <= 100


class TestAlertThresholds:
    """Tests for alert/analysis threshold functions."""

    def test_should_alert_above_threshold(self):
        assert should_alert(ALERT_THRESHOLD) is True
        assert should_alert(ALERT_THRESHOLD + 1) is True
        assert should_alert(100) is True

    def test_should_not_alert_below_threshold(self):
        assert should_alert(ALERT_THRESHOLD - 1) is False
        assert should_alert(0) is False

    def test_should_deep_analyze_above_threshold(self):
        assert should_deep_analyze(DEEP_ANALYSIS_THRESHOLD) is True
        assert should_deep_analyze(100) is True

    def test_should_not_deep_analyze_below_threshold(self):
        assert should_deep_analyze(DEEP_ANALYSIS_THRESHOLD - 1) is False
        assert should_deep_analyze(0) is False
