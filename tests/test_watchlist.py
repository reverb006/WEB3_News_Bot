"""
Unit tests for Custom Watchlist functionality in SQLite database.
"""

from __future__ import annotations

import pytest
from app.database.db import Database


@pytest.mark.asyncio
async def test_watchlist_crud():
    db = Database(":memory:")
    await db.initialize()

    # Initially empty
    keywords = await db.get_watchlist_keywords()
    assert keywords == []

    # Add keywords
    res1 = await db.add_watchlist_keyword("flash loan")
    assert res1 is True

    res2 = await db.add_watchlist_keyword("reentrancy")
    assert res2 is True

    # Duplicate should return False
    res3 = await db.add_watchlist_keyword("flash loan")
    assert res3 is False

    # List keywords
    keywords = await db.get_watchlist_keywords()
    assert "flash loan" in keywords
    assert "reentrancy" in keywords
    assert len(keywords) == 2

    # Check match
    match1 = await db.check_watchlist_match("Attacker executed a flash loan on Uniswap v2 pool")
    assert match1 == "flash loan"

    match2 = await db.check_watchlist_match("Standard governance vote passed")
    assert match2 is None

    # Remove keyword
    del_res = await db.remove_watchlist_keyword("flash loan")
    assert del_res is True

    keywords_after = await db.get_watchlist_keywords()
    assert "flash loan" not in keywords_after
    assert len(keywords_after) == 1

    await db.close()
