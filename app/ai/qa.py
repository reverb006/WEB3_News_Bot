"""
Auditor Q&A Engine — Interactive smart contract security intelligence powered by Gemini.

Allows auditors to ask technical questions about past exploits, root causes,
vulnerable smart-contract patterns, invariant testing, and audit checklists directly via Telegram.
"""

from __future__ import annotations

import html
import logging
import re
from pathlib import Path
from typing import Optional

from google import genai
from google.genai import types

from app.config.settings import get_settings
from app.database.db import Database

logger = logging.getLogger(__name__)

REPORTS_DIR = Path(__file__).resolve().parent.parent.parent / "reports"

QA_SYSTEM_PROMPT = """You are Web3 Security Radar AI, an elite smart contract security auditor and vulnerability researcher assistant.
Your user is a smart contract auditor analyzing Web3 exploits, studying invariant testing, and auditing Solidity protocols.

Your goals:
1. Provide technically precise, insightful answers focusing on root causes, smart contract mechanics, vulnerable code patterns, and invariant design.
2. If the user asks about a specific incident (e.g. Liquid Network, Curve, xWin, PolyNetwork, etc.), leverage the provided context from the database and case study archives.
3. Keep answers concise, actionable, and structured for an auditor (mention Protocol, Attack Vector, Root Cause, Violated Invariant, and Audit Lesson).
4. Format strictly using Telegram-supported HTML tags:
   - <b>bold text</b> for headings and keywords
   - <i>italic</i> for explanations or summaries
   - <code>code snippets or function names</code>
   - <pre>multiline code blocks</pre>
   Do NOT use Markdown asterisks (**) or backticks (```), as Telegram HTML parse mode will fail.
"""


def _extract_keywords(query: str) -> list[str]:
    """Extract significant keywords from user query for SQLite search."""
    stopwords = {
        "what", "wht", "how", "why", "when", "where", "who", "which", "is", "are", "was",
        "were", "the", "a", "an", "and", "or", "in", "on", "at", "to", "for", "of",
        "about", "tell", "me", "show", "can", "you", "explain", "did", "happened",
        "hack", "exploit", "incident", "vulnerability", "attacks", "attack",
    }
    words = re.findall(r"\b[A-Za-z0-9_]{3,}\b", query)
    return [w for w in words if w.lower() not in stopwords]


async def retrieve_context(query: str, db: Optional[Database]) -> str:
    """Retrieve relevant incident context only if an incident ID is explicitly referenced."""
    if not db or not getattr(db, "conn", None):
        return ""

    # Check for specific incident ID reference like #123 or incident 123
    id_match = re.search(r"#(\d+)|incident\s+(\d+)", query, re.IGNORECASE)
    if not id_match:
        return ""

    inc_id = int(id_match.group(1) or id_match.group(2))
    try:
        cursor = await db.conn.execute(
            """
            SELECT id, title, protocol, chain, attack_type, estimated_loss_usd,
                   severity, deep_analysis, first_seen_at
            FROM incidents
            WHERE id = ?
            """,
            (inc_id,),
        )
        row = await cursor.fetchone()
        if not row:
            return ""

        columns = [desc[0] for desc in cursor.description]
        inc = dict(zip(columns, row))
        proto = inc.get("protocol") or "Protocol"
        title = inc.get("title") or "Incident"
        loss = inc.get("estimated_loss_usd")
        loss_str = f"${loss:,.2f}" if loss else "Undisclosed"
        attack = inc.get("attack_type") or "Unspecified"
        date_str = (inc.get("first_seen_at") or "")[:10]
        chunk = f"[Database Record Incident #{inc_id} ({date_str}): {title} | Protocol: {proto} | Loss: {loss_str} | Attack: {attack}]"

        slug = "".join(c for c in proto.lower() if c.isalnum() or c == "_")
        report_file = REPORTS_DIR / f"incident_{inc_id}_{slug}.md"
        if report_file.exists():
            chunk += f"\nDeep Analysis: {report_file.read_text(encoding='utf-8')[:400]}..."
        elif inc.get("deep_analysis"):
            chunk += f"\nDeep Analysis: {inc['deep_analysis'][:400]}..."

        return chunk
    except Exception as e:
        logger.warning(f"Error retrieving incident context for #{inc_id}: {e}")
        return ""


async def ask_auditor(question: str, db: Optional[Database] = None) -> str:
    """
    Answer an auditor's technical query using Gemini AI directly for instant speed.
    Bypasses slow database scans and disk reads so queries return in ~2-4 seconds.
    """
    settings = get_settings()
    if not settings.has_gemini:
        return "❌ <b>Gemini API key not configured</b> in .env. Cannot process AI questions."

    clean_q = question.strip()
    if not clean_q:
        return "Please ask a question after /ask. Example:\n<code>/ask How did the Liquid Network exploit happen?</code>"

    # Fast check: Only check database if user specifically asked for an incident ID (e.g. #102)
    incident_context = await retrieve_context(clean_q, db) if db else ""
    if incident_context:
        prompt = f"""AUDITOR QUERY:
{clean_q}

RELEVANT INCIDENT RECORD:
{incident_context}

Provide an auditor-level technical breakdown with root cause, vulnerable pattern, violated invariant, and audit lessons."""
    else:
        prompt = f"""AUDITOR QUERY:
{clean_q}

Provide a comprehensive, technically rigorous auditor analysis. Focus on protocol architecture, exploit mechanics, root cause, vulnerable contract code pattern, violated invariant, and audit prevention lessons."""

    # Models to try in order of preference if Google returns high-demand 503
    primary_model = getattr(settings, "gemini_model", "gemini-3.5-flash") or "gemini-3.5-flash"
    candidate_models = [primary_model, "gemini-3-flash-preview", "gemini-3.1-flash-lite"]
    # De-duplicate while preserving order
    models_to_try = []
    for m in candidate_models:
        if m and m not in models_to_try:
            models_to_try.append(m)

    client = genai.Client(api_key=settings.gemini_api_key)
    last_error = None

    for model_name in models_to_try:
        try:
            response = await client.aio.models.generate_content(
                model=model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=QA_SYSTEM_PROMPT,
                    temperature=0.2,
                    max_output_tokens=2500,
                    thinking_config=types.ThinkingConfig(thinking_budget=0),
                ),
            )

            answer = response.text.strip()
            # Clean up markdown asterisks and backticks for Telegram HTML compatibility
            answer = answer.replace("**", "<b>").replace("__", "<i>")
            return answer

        except Exception as e:
            err_str = str(e)
            last_error = e
            if "503" in err_str or "UNAVAILABLE" in err_str or "404" in err_str:
                logger.warning(f"Model {model_name} unavailable ({err_str[:60]}), falling back to next candidate...")
                continue
            else:
                logger.error(f"Error generating answer with {model_name}: {e}", exc_info=True)
                break

    return f"⚠️ <b>Error processing query:</b> {html.escape(str(last_error))}"

