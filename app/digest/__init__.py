"""
Digest package — daily Web3 security intelligence summaries.
"""

from app.digest.daily import DailyDigestGenerator, run_daily_digest

__all__ = ["DailyDigestGenerator", "run_daily_digest"]
