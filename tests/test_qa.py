"""
Unit tests for Auditor Q&A engine.
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from app.database.db import Database
from app.ai.qa import _extract_keywords, retrieve_context, ask_auditor


def test_extract_keywords():
    query = "How did the Liquid Network exploit happen and what was the root cause?"
    kws = _extract_keywords(query)
    assert "liquid" in [k.lower() for k in kws]
    assert "network" in [k.lower() for k in kws]
    assert "root" in [k.lower() for k in kws]
    assert "cause" in [k.lower() for k in kws]
    # Stopwords filtered
    assert "how" not in [k.lower() for k in kws]
    assert "did" not in [k.lower() for k in kws]


@pytest.mark.asyncio
async def test_retrieve_context():
    db = Database(":memory:")
    await db.initialize()

    # Create test incident
    inc_id = await db.create_incident(
        title="Liquid Network $320M Exploit",
        protocol="Liquid Network",
        chain=["Bitcoin"],
        attack_type=["RESERVE_DRAIN"],
        estimated_loss_usd=320_000_000.0,
        severity="CRITICAL",
        status="active",
    )

    # General query bypasses database to stay fast
    general_ctx = await retrieve_context("tell me about Liquid Network", db)
    assert general_ctx == ""

    # Specific incident ID query retrieves exact record
    id_ctx = await retrieve_context(f"tell me about #{inc_id}", db)
    assert "Liquid Network" in id_ctx
    assert "$320,000,000.00" in id_ctx

    await db.close()


@pytest.mark.asyncio
async def test_ask_auditor_mock(monkeypatch):
    import app.ai.qa as qa_mod

    mock_settings = MagicMock()
    mock_settings.has_gemini = True
    mock_settings.gemini_api_key = "test-gemini-key"
    mock_settings.gemini_model = "gemini-3.5-flash"
    monkeypatch.setattr(qa_mod, "get_settings", lambda: mock_settings)

    db = Database(":memory:")
    await db.initialize()

    mock_response = MagicMock()
    mock_response.text = "<b>Root Cause:</b> Reentrancy vulnerability in the withdrawal hook."

    with patch("google.genai.Client") as mock_client_cls:
        mock_instance = MagicMock()
        mock_instance.aio.models.generate_content = AsyncMock(return_value=mock_response)
        mock_client_cls.return_value = mock_instance

        answer = await ask_auditor("Explain the bug in the vault", db)
        assert "<b>Root Cause:</b>" in answer
        assert "Reentrancy vulnerability" in answer

    await db.close()
