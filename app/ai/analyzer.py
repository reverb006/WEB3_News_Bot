"""
Gemini Deep Analyzer — generates auditor-grade case studies for critical Web3 exploits.

Features:
- Produces in-depth root cause, attack sequence, auditor lessons, and Foundry/Slither invariants
- Saves full markdown case study reports to the `reports/` folder
- Formats concise Telegram Deep Briefings for quick mobile reading
- Stores structured case study into SQLite (`incidents.deep_analysis`)
"""

from __future__ import annotations

import asyncio
import html
import json
import logging
import re
from pathlib import Path
from typing import Optional

from google import genai
from google.genai import types

from app.config.settings import get_settings, PROJECT_ROOT
from app.database.db import Database
from app.models.schemas import DeepAnalysis

logger = logging.getLogger(__name__)

REPORTS_DIR = PROJECT_ROOT / "reports"

AUDITOR_SYSTEM_PROMPT = """You are a Principal Smart-Contract Security Auditor and Web3 Protocol Exploit Specialist (ex-Trail of Bits, OpenZeppelin).
Your job is to produce an exhaustive, authoritative, code-level technical case study of the provided Web3 security incident.

Your audience is smart-contract security auditors, protocol researchers, and bug bounty hunters.
Focus on:
1. Exact technical mechanics (e.g., read-only reentrancy, compiler code-gen flaw, missing storage gap, rounding direction, oracle flash manipulation).
2. Step-by-step execution flow of the attacker.
3. Concrete auditor takeaways (what specific patterns to check during an audit).
4. Invariants and mitigations (how to test with Foundry invariants or Slither).

Be technically precise. Do not output vague fluff. If technical details are not fully confirmed in the provided text, note them as suspected or pending full post-mortem."""


class GeminiDeepAnalyzer:
    """
    Analyzes critical security incidents using Gemini and generates auditor case studies.
    """

    MODEL_FALLBACK = [
        "gemini-3.5-flash",
        "gemini-3.6-flash",
        "gemini-3.8-flash",
    ]

    API_TIMEOUT = 60  # Deep analysis prompts are longer

    def __init__(self):
        settings = get_settings()
        if not settings.has_gemini:
            raise ValueError("Gemini API key not configured in .env file.")

        self._client = genai.Client(api_key=settings.gemini_api_key)
        preferred = getattr(settings, "gemini_model", "") or ""
        self._models = list(dict.fromkeys(([preferred] if preferred else []) + self.MODEL_FALLBACK))

    async def analyze_incident(
        self,
        incident: dict,
        articles: list[dict],
    ) -> Optional[DeepAnalysis]:
        """
        Generate a structured DeepAnalysis for an incident based on its collected articles.

        Args:
            incident: Incident record dict.
            articles: List of related article dicts with content and sources.

        Returns:
            DeepAnalysis Pydantic object or None if failed.
        """
        title = incident.get("title") or "Unnamed Incident"
        protocol = incident.get("protocol") or "Unknown Protocol"
        loss = incident.get("estimated_loss_usd")
        loss_str = f"${loss:,.2f}" if loss else "Undisclosed / Unknown"

        # Aggregate context from all corroborating articles (up to 8,000 chars to conserve tokens)
        context_parts = []
        for i, art in enumerate(articles, 1):
            src = art.get("source_name", "Unknown Source")
            art_title = art.get("title", "")
            art_content = (art.get("content") or "")[:2500]
            context_parts.append(
                f"--- SOURCE {i}: {src} ---\nTITLE: {art_title}\nCONTENT:\n{art_content}\n"
            )

        combined_context = "\n".join(context_parts)[:8000]

        user_prompt = f"""INCIDENT: {title}
TARGET PROTOCOL: {protocol}
ESTIMATED FINANCIAL LOSS: {loss_str}

REPORTS & POST-MORTEMS:
{combined_context}

Analyze this incident thoroughly and output a structured case study matching the schema."""

        last_error = None
        models_to_try = getattr(self, "_models", self.MODEL_FALLBACK)
        for model in models_to_try:
            try:
                logger.info(f"Generating Deep Analysis for '{title[:45]}' using {model}...")
                response = await asyncio.wait_for(
                    asyncio.to_thread(
                        self._client.models.generate_content,
                        model=model,
                        contents=user_prompt,
                        config=types.GenerateContentConfig(
                            system_instruction=AUDITOR_SYSTEM_PROMPT,
                            response_mime_type="application/json",
                            response_schema=DeepAnalysis,
                            temperature=0.2,
                        ),
                    ),
                    timeout=self.API_TIMEOUT,
                )

                if response.parsed:
                    logger.info(f"Deep Analysis generated successfully with {model}!")
                    return response.parsed

                if response.text:
                    try:
                        data = json.loads(response.text)
                        return DeepAnalysis(**data)
                    except Exception as e:
                        logger.error(f"Failed to parse Deep Analysis JSON from {model}: {e}")

            except Exception as e:
                last_error = e
                err_str = str(e)
                if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str:
                    match = re.search(r"retry in (\d+(?:\.\d+)?)s", err_str, re.IGNORECASE)
                    wait = max(float(match.group(1)) + 1.5, 12.0) if match else 12.0
                    logger.info(f"[RATE-LIMIT] Cooling down {wait:.0f}s for deep analysis on {model}...")
                    await asyncio.sleep(wait)
                elif "503" in err_str or "UNAVAILABLE" in err_str:
                    logger.info(f"[BUSY] Model {model} temporarily busy (503). Retrying fallback in 3s...")
                    await asyncio.sleep(3.0)
                else:
                    first_line = err_str.split("\n")[0][:80]
                    logger.warning(f"[FALLBACK] Model {model} failed for deep analysis ({first_line}), trying fallback...")
                    await asyncio.sleep(2.0)


        first_err = str(last_error).split("\n")[0][:80] if last_error else "Unknown error"
        logger.warning(f"Could not generate Deep Analysis across fallback models: {first_err}")
        return None


    def generate_markdown_report(
        self,
        incident: dict,
        analysis: DeepAnalysis,
        articles: list[dict],
    ) -> str:
        """
        Render a publication-grade Markdown case study document.
        """
        title = incident.get("title") or "Security Incident"
        protocol = incident.get("protocol") or "Web3 Protocol"
        loss = incident.get("estimated_loss_usd")
        loss_str = f"${loss:,.2f}" if loss else "Undisclosed"
        severity = (incident.get("severity") or "CRITICAL").upper()
        inc_id = incident.get("id")

        lines = [
            f"# Exploit Case Study #{inc_id}: {title}",
            "",
            f"**Target Protocol:** {protocol}  ",
            f"**Severity:** `{severity}` | **Estimated Loss:** `{loss_str}`  ",
            f"**First Detected:** {incident.get('first_seen_at', 'N/A')}  ",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            "",
            analysis.executive_summary,
            "",
            "## 2. Technical Root Cause Analysis",
            "",
            analysis.root_cause_analysis,
            "",
            "## 3. Attack Execution Flow",
            "",
        ]

        for i, step in enumerate(analysis.attack_vector_steps, 1):
            lines.append(f"{i}. {step}")

        lines.extend([
            "",
            "## 4. Vulnerable Components & Interfaces",
            "",
        ])
        for comp in analysis.vulnerable_components:
            lines.append(f"- `{comp}`")

        lines.extend([
            "",
            "## 5. Auditor Takeaways & Checklist",
            "",
        ])
        for lesson in analysis.auditor_lessons:
            lines.append(f"- 🔍 **Audit Focus:** {lesson}")

        lines.extend([
            "",
            "## 6. Recommended Invariants & Mitigations",
            "",
        ])
        for mit in analysis.mitigations_and_invariants:
            lines.append(f"- 🛡️ **Invariant / Patch:** {mit}")

        if analysis.affected_ecosystems:
            lines.extend([
                "",
                "## 7. Affected Ecosystems & Forks",
                "",
            ])
            for eco in analysis.affected_ecosystems:
                lines.append(f"- {eco}")

        lines.extend([
            "",
            "---",
            "",
            "## References & Corroborating Sources",
            "",
        ])
        for art in articles:
            s_name = art.get("source_name", "Source")
            url = art.get("url", "#")
            a_title = art.get("title", "Article")
            lines.append(f"- [{s_name}] [{a_title}]({url})")

        lines.append("")
        return "\n".join(lines)

    def save_report_file(self, incident: dict, markdown_content: str) -> Path:
        """
        Save markdown case study to the reports/ directory.
        """
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        inc_id = incident.get("id", 0)
        proto_slug = "".join(
            c for c in (incident.get("protocol") or "incident").lower() if c.isalnum() or c == "_"
        )
        filename = f"incident_{inc_id}_{proto_slug}.md"
        file_path = REPORTS_DIR / filename
        file_path.write_text(markdown_content, encoding="utf-8")
        logger.info(f"Saved case study report to: {file_path}")
        return file_path

    def format_telegram_briefing(self, incident: dict, analysis: DeepAnalysis) -> str:
        """
        Format a concise, high-value Telegram message with the key case study takeaways.
        """
        title = html.escape(incident.get("title") or "Security Incident")
        protocol = incident.get("protocol") or "Web3 Protocol"
        loss = incident.get("estimated_loss_usd")
        loss_str = f"${loss:,.2f}" if loss else "Undisclosed"
        clean_tag = "".join(c for c in protocol if c.isalnum())

        lines = [
            "🔬 <b>DEEP AUDIT CASE STUDY AVAILABLE</b>",
            "",
            f"<b>{title}</b>",
            f"🎯 <b>Protocol:</b> #{clean_tag} | 💰 <b>Loss:</b> {loss_str}",
            "",
            "📌 <b>Executive Summary:</b>",
            f"<i>{html.escape(analysis.executive_summary)}</i>",
            "",
            "⚡ <b>Root Cause:</b>",
            f"<code>{html.escape(analysis.root_cause_analysis[:350])}...</code>",
            "",
            "🔍 <b>Auditor Checklist Takeaways:</b>",
        ]

        for lesson in analysis.auditor_lessons[:3]:
            lines.append(f"• {html.escape(lesson)}")

        lines.extend([
            "",
            "🛡️ <b>Key Invariant:</b>",
            f"<i>{html.escape(analysis.mitigations_and_invariants[0] if analysis.mitigations_and_invariants else 'Ensure non-reentrancy on all state-mutating functions.')}</i>",
            "",
            "📄 <i>Full technical report saved to local reports/ directory.</i>",
        ])

        return "\n".join(lines)


async def run_incident_deep_analysis(
    incident_id: int,
    db: Database,
    send_telegram: bool = True,
) -> Optional[Path]:
    """
    Convenience function to analyze an incident, save to SQLite, write markdown, and notify Telegram.
    """
    incident = await db.get_incident(incident_id)
    if not incident:
        logger.error(f"Incident #{incident_id} not found in database.")
        return None

    articles = await db.get_incident_articles(incident_id)
    analyzer = GeminiDeepAnalyzer()

    analysis = await analyzer.analyze_incident(incident, articles)
    if not analysis:
        logger.error(f"Deep analysis failed for Incident #{incident_id}")
        return None

    # Save structured JSON into SQLite
    await db.save_incident_analysis(incident_id, analysis.model_dump_json(indent=2))

    # Generate and save markdown report
    md_report = analyzer.generate_markdown_report(incident, analysis, articles)
    report_path = analyzer.save_report_file(incident, md_report)

    # Dispatch Telegram briefing if requested
    if send_telegram:
        settings = get_settings()
        if settings.has_telegram:
            from app.alerts.telegram import TelegramAlertManager
            mgr = TelegramAlertManager()
            briefing_msg = analyzer.format_telegram_briefing(incident, analysis)
            await mgr.send_message(briefing_msg)

    return report_path
