"""Processing module — priority scoring, deduplication, and incident merging."""

from app.processing.priority import compute_priority, should_alert, should_deep_analyze
from app.processing.deduplication import (
    IncidentManager,
    compute_title_similarity,
    are_articles_related,
    normalize_title,
)

__all__ = [
    "compute_priority",
    "should_alert",
    "should_deep_analyze",
    "IncidentManager",
    "compute_title_similarity",
    "are_articles_related",
    "normalize_title",
]
