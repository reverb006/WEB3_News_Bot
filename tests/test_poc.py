"""
Unit tests for Foundry PoC Generator.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock
import pytest

from app.database.db import Database
from app.ai.poc_generator import _sanitize_solidity_code, generate_foundry_poc


def test_sanitize_solidity_code():
    raw_markdown = """Here is the code:
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";

contract ExploitTest is Test {
    function test_exploit() public {}
}
```
Good luck!
"""
    clean = _sanitize_solidity_code(raw_markdown)
    assert clean.startswith("// SPDX-License-Identifier: MIT")
    assert "contract ExploitTest is Test" in clean
    assert "Good luck!" not in clean


@pytest.mark.asyncio
async def test_generate_foundry_poc_mock(tmp_path, monkeypatch):
    import app.ai.poc_generator as poc_mod

    monkeypatch.setattr(poc_mod, "POCS_DIR", tmp_path)
    mock_settings = MagicMock()
    mock_settings.has_gemini = True
    mock_settings.gemini_api_key = "test-gemini-key"
    mock_settings.gemini_model = "gemini-3.5-flash"
    monkeypatch.setattr(poc_mod, "get_settings", lambda: mock_settings)

    db = Database(":memory:")
    await db.initialize()

    inc_id = await db.create_incident(
        title="Mock DeFi Protocol Flash Loan Drain",
        protocol="MockDeFi",
        chain=["Ethereum"],
        attack_type=["FLASH_LOAN_MANIPULATION"],
        estimated_loss_usd=5_000_000.0,
        severity="CRITICAL",
        status="active",
    )

    mock_solidity = """```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";

contract PoC_MockDeFi is Test {
    function setUp() public {}
    function test_exploit() public {
        assertTrue(true);
    }
}
```"""

    mock_resp = MagicMock()
    mock_resp.text = mock_solidity

    with patch("google.genai.Client") as mock_client_cls:
        mock_instance = MagicMock()
        mock_instance.aio.models.generate_content = AsyncMock(return_value=mock_resp)
        mock_client_cls.return_value = mock_instance

        file_path = await generate_foundry_poc(inc_id, db)
        assert file_path is not None
        assert file_path.exists()
        assert file_path.name.endswith(".t.sol")

        content = file_path.read_text(encoding="utf-8")
        assert "contract PoC_MockDeFi is Test" in content

    await db.close()
