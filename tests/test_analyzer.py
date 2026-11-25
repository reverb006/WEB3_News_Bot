"""
Tests for deep analysis report generation and incident analysis storage.
"""

import pytest
from app.models.schemas import DeepAnalysis
from app.ai.analyzer import GeminiDeepAnalyzer
from app.database.db import Database


class TestDeepAnalysisFormatting:
    """Test markdown report rendering and telegram briefing formatting."""

    def _sample_analysis(self) -> DeepAnalysis:
        return DeepAnalysis(
            executive_summary="Curve Finance suffered a $60M exploit across several liquidity pools due to a reentrancy lock bug.",
            root_cause_analysis="The @nonreentrant decorator in Vyper 0.2.15-0.3.0 allocated storage slots incorrectly, allowing reentrant calls.",
            attack_vector_steps=[
                "Attacker takes a flash loan of 10,000 WETH",
                "Attacker calls remove_liquidity to initiate state transition",
                "Callback reenters the contract before balances are adjusted",
                "Attacker drains excess LP tokens and repays loan",
            ],
            vulnerable_components=[
                "Curve StableSwap Vyper contract",
                "@nonreentrant lock implementation",
            ],
            auditor_lessons=[
                "Verify compiler release notes and known compiler CVEs.",
                "Do not rely solely on source code inspection without verifying compiled bytecode behaviors.",
            ],
            mitigations_and_invariants=[
                "Upgrade to Vyper 0.3.10+ where the slot allocation issue is resolved.",
                "Foundry Invariant: assertEq(pool.get_virtual_price(), expectedPrice) across all calls.",
            ],
            affected_ecosystems=["Ethereum", "Arbitrum", "Optimism"],
        )

    def test_markdown_report_structure(self, tmp_path):
        incident = {
            "id": 42,
            "title": "Curve Finance Exploited for $60M",
            "protocol": "Curve Finance",
            "estimated_loss_usd": 60000000.0,
            "severity": "CRITICAL",
            "first_seen_at": "2026-09-22 10:00:00",
        }
        articles = [
            {
                "source_name": "PeckShield",
                "title": "Curve Finance alETH pool exploit",
                "url": "https://peckshield.com/curve",
            }
        ]

        analyzer = GeminiDeepAnalyzer.__new__(GeminiDeepAnalyzer)
        analysis = self._sample_analysis()

        md = analyzer.generate_markdown_report(incident, analysis, articles)

        assert "# Exploit Case Study #42: Curve Finance Exploited for $60M" in md
        assert "## 1. Executive Summary" in md
        assert "## 2. Technical Root Cause Analysis" in md
        assert "## 3. Attack Execution Flow" in md
        assert "## 4. Vulnerable Components & Interfaces" in md
        assert "## 5. Auditor Takeaways & Checklist" in md
        assert "## 6. Recommended Invariants & Mitigations" in md
        assert "## 7. Affected Ecosystems & Forks" in md
        assert "Foundry Invariant:" in md
        assert "[PeckShield]" in md
        assert "https://peckshield.com/curve" in md

    def test_telegram_briefing_formatting(self):
        incident = {
            "title": "Curve Finance Reentrancy Flaw",
            "protocol": "Curve Finance",
            "estimated_loss_usd": 60000000.0,
        }
        analyzer = GeminiDeepAnalyzer.__new__(GeminiDeepAnalyzer)
        analysis = self._sample_analysis()

        briefing = analyzer.format_telegram_briefing(incident, analysis)

        assert "DEEP AUDIT CASE STUDY AVAILABLE" in briefing
        assert "#CurveFinance" in briefing
        assert "$60,000,000.00" in briefing
        assert "Auditor Checklist Takeaways:" in briefing


@pytest.mark.asyncio
class TestDeepAnalysisDatabase:
    """Test database recording of deep analysis."""

    async def test_save_incident_analysis(self, tmp_path):
        db = Database(tmp_path / "test_analysis.db")
        await db.initialize()

        inc_id = await db.create_incident(
            title="Euler Finance Exploit",
            protocol="Euler",
            estimated_loss_usd=197000000.0,
            severity="CRITICAL",
        )

        sample_json = '{"executive_summary": "Euler exploit drained $197M via donation logic."}'
        await db.save_incident_analysis(inc_id, sample_json)

        inc = await db.get_incident(inc_id)
        assert inc["deep_analysis"] == sample_json
        assert inc["analyzed_at"] is not None

        await db.close()
