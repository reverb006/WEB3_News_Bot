"""
Priority Scoring — computes a 0-100 score for each classified article.

The score determines:
  - Whether a Telegram alert is sent (score >= 70)
  - Whether deep analysis is triggered (score >= 80)
  - Sort order in the daily digest
  - What you see first as an auditor

The algorithm weights factors that matter to a smart-contract security
auditor, NOT what's "trending" or "popular". A $50M bridge hack from
PeckShield scores higher than a viral tweet about NFT prices.

Score breakdown (max 100):
  - Category weight:      0-40 points (CRITICAL=40, HIGH=30, etc.)
  - Financial loss:       0-20 points (scaled by loss amount)
  - Source reliability:   0-15 points (PeckShield > random tweet)
  - Security relevance:   0-15 points (from Gemini's assessment)
  - Active attack bonus:  0-10 points (ongoing = more urgent)
"""

from __future__ import annotations

import logging

from app.models.schemas import Classification, Category, IncidentStatus

logger = logging.getLogger(__name__)

# How many points each category is worth (max 40)
CATEGORY_WEIGHTS: dict[Category, int] = {
    Category.CRITICAL_SECURITY: 40,
    Category.HIGH_SECURITY: 30,
    Category.SECURITY_RESEARCH: 20,
    Category.PROTOCOL_UPDATE: 15,
    Category.MAJOR_WEB3_NEWS: 10,
    Category.REGULATION: 5,
    Category.MARKET: 0,
    Category.LOW_VALUE: 0,
    Category.IGNORE: 0,
}

# Financial loss thresholds and their point values
LOSS_THRESHOLDS: list[tuple[float, int]] = [
    (100_000_000, 20),   # $100M+ → 20 points
    (10_000_000, 15),    # $10M+  → 15 points
    (1_000_000, 10),     # $1M+   → 10 points
    (100_000, 5),        # $100K+ → 5 points
    (0, 0),              # Less   → 0 points
]

# Alerts are sent for articles with priority >= this threshold
ALERT_THRESHOLD = 70

# Deep analysis is triggered for articles with priority >= this threshold
DEEP_ANALYSIS_THRESHOLD = 80


def compute_priority(
    classification: Classification,
    source_reliability: int = 50,
) -> int:
    """
    Compute a priority score (0-100) for a classified article.

    Args:
        classification: The Gemini classification result.
        source_reliability: The source's reliability score (0-100).

    Returns:
        Priority score from 0 (ignore) to 100 (drop everything and read this).
    """
    score = 0

    # --- Category weight (0-40 points) ---
    # This is the biggest factor. A critical exploit starts at 40,
    # while market news starts at 0.
    category_points = CATEGORY_WEIGHTS.get(classification.category, 0)
    score += category_points

    # --- Financial loss (0-20 points) ---
    # Bigger losses = more important. A $100M hack is more urgent
    # than a $10K exploit, even if both are "critical".
    if classification.estimated_loss_usd is not None:
        for threshold, points in LOSS_THRESHOLDS:
            if classification.estimated_loss_usd >= threshold:
                score += points
                break

    # --- Source reliability (0-15 points) ---
    # Trail of Bits (85) gets ~13 points; random news (40) gets ~6.
    # This ensures primary sources rank higher than rumors.
    source_points = int(source_reliability * 0.15)
    score += source_points

    # --- Security relevance from Gemini (0-15 points) ---
    # Gemini scores how relevant this is to smart-contract security (0-100).
    # We scale that to 0-15 points.
    relevance_points = int(classification.security_relevance * 0.15)
    score += relevance_points

    # --- Active attack bonus (0-10 points) ---
    # If an attack is actively happening RIGHT NOW, it's more urgent.
    if classification.status == IncidentStatus.ACTIVE:
        score += 10

    # Clamp to [0, 100]
    final_score = max(0, min(100, score))

    logger.debug(
        f"Priority score={final_score} "
        f"(cat={category_points}, loss={score - category_points - source_points - relevance_points}, "
        f"src={source_points}, rel={relevance_points})"
    )

    return final_score


def should_alert(priority_score: int) -> bool:
    """Whether this article should trigger a real-time Telegram alert."""
    return priority_score >= ALERT_THRESHOLD


def should_deep_analyze(priority_score: int) -> bool:
    """Whether this article should get a full Gemini deep analysis."""
    return priority_score >= DEEP_ANALYSIS_THRESHOLD
