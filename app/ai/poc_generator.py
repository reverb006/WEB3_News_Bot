"""
Foundry PoC Generator — Auto-generates reproducible Foundry test skeletons for smart contract exploits.

Produces complete Solidity test files with forge-std imports, contract interfaces,
fork setup, attacker address, exploit step execution, and state invariant assertions.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

from google import genai
from google.genai import types

from app.config.settings import get_settings
from app.database.db import Database

logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
POCS_DIR = ROOT_DIR / "pocs"

FOUNDRY_POC_SYSTEM_PROMPT = """You are an elite smart contract security auditor specializing in Foundry / Forge exploit reproduction and invariant testing.
Your task is to generate a clean, compilable, and educational Foundry PoC (Proof-of-Concept) Solidity test file that demonstrates how a reported Web3 exploit occurred.

Output Requirements:
1. Solidity version: `pragma solidity ^0.8.20;`
2. Import forge-std: `import {Test, console2} from "forge-std/Test.sol";`
3. Define minimal target protocol interfaces necessary to interact with the vulnerable function.
4. Name the test contract `PoC_Exploit_Incident` inheriting from `Test`.
5. Implement `setUp()`:
   - Include fork creation placeholder: `// vm.createSelectFork("mainnet", BLOCK_NUMBER);`
   - Setup attacker address: `address attacker = makeAddr("attacker");`
   - Deal test funds: `vm.deal(attacker, 10 ether);`
6. Implement `test_exploit()`:
   - Step 1: Pre-exploit state checks / balance logging (`console2.log`)
   - Step 2: Flash loan or malicious payload execution simulating the attacker
   - Step 3: Post-exploit state checks asserting attacker gain or protocol loss (`assertGt`, `assertLt`, or `assertEq`)
7. Add a clear top comment with:
   - Target Protocol
   - Exploit Summary & Root Cause
   - Invariant Violated
   - Command to run: `forge test --match-test test_exploit -vvvv`
8. Return ONLY the raw Solidity code inside ```solidity ... ``` code block. Do NOT include extraneous conversational filler.
"""


def _sanitize_solidity_code(raw_text: str) -> str:
    """Extract clean Solidity code from model output."""
    match = re.search(r"```(?:solidity)?\s*(.*?)\s*```", raw_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return raw_text.strip()


async def generate_foundry_poc(incident_id: int, db: Database) -> Optional[Path]:
    """
    Generate and save a Foundry PoC test file for a given incident ID.
    """
    settings = get_settings()
    if not settings.has_gemini:
        logger.error("Gemini API key not configured. Cannot generate Foundry PoC.")
        return None

    incident = await db.get_incident(incident_id)
    if not incident:
        logger.warning(f"Incident #{incident_id} not found in database.")
        return None

    articles = await db.get_incident_articles(incident_id)
    proto = incident.get("protocol") or "Protocol"
    title = incident.get("title") or "Security Incident"
    loss = incident.get("estimated_loss_usd")
    loss_str = f"${loss:,.2f}" if loss else "Undisclosed"
    attack = incident.get("attack_type") or "Unspecified"
    deep_analysis = incident.get("deep_analysis") or ""

    articles_summary = "\n".join(
        f"- {a.get('title')}: {a.get('summary', '')[:200]}" for a in articles[:3]
    )

    prompt = f"""Generate a Foundry PoC test skeleton for:
INCIDENT #{incident_id}: {title}
PROTOCOL: {proto}
ESTIMATED LOSS: {loss_str}
ATTACK VECTOR: {attack}

DEEP AUDITOR ANALYSIS:
{deep_analysis[:1200] if deep_analysis else 'No deep analysis record.'}

CORROBORATING ARTICLES:
{articles_summary}

Write the complete Solidity PoC test file now."""

    try:
        client = genai.Client(api_key=settings.gemini_api_key)
        target_model = getattr(settings, "gemini_model", "gemini-3.5-flash") or "gemini-3.5-flash"
        response = await client.aio.models.generate_content(
            model=target_model,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=FOUNDRY_POC_SYSTEM_PROMPT,
                temperature=0.2,
                max_output_tokens=3000,
                thinking_config=types.ThinkingConfig(thinking_budget=0),
            ),
        )

        code = _sanitize_solidity_code(response.text)

        # Save to pocs/ directory
        POCS_DIR.mkdir(parents=True, exist_ok=True)
        proto_slug = "".join(c for c in proto.lower() if c.isalnum() or c == "_")
        file_path = POCS_DIR / f"PoC_Incident_{incident_id}_{proto_slug}.t.sol"
        file_path.write_text(code, encoding="utf-8")

        logger.info(f"Generated Foundry PoC saved to: {file_path}")
        return file_path

    except Exception as e:
        logger.error(f"Failed to generate Foundry PoC for Incident #{incident_id}: {e}", exc_info=True)
        return None
