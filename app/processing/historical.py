"""
Historical Exploit Importer — Ingests 800+ curated Web3 exploits (2020 to 2026).

Sources data from DeFiHackLabs and security research archives, populating:
- Database `sources`, `articles`, and `incidents` with accurate historical dates (2020–2026)
- Root causes, attack vectors, estimated losses, and Foundry reproduction links
- Full synchronization with `reports/archive_security.md`
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any

from app.database.db import Database
from app.models.schemas import SourceType

logger = logging.getLogger(__name__)

HISTORICAL_SOURCE_NAME = "DeFiHackLabs Historical Archive"
HISTORICAL_SOURCE_URL = "https://github.com/SunWeb3Sec/DeFiHackLabs"

YEAR_URLS = {
    "2026": "https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main/README.md",
    "2025": "https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main/past/2025/README.md",
    "2024": "https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main/past/2024/README.md",
    "2023": "https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main/past/2023/README.md",
    "2022": "https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main/past/2022/README.md",
    "2021": "https://raw.githubusercontent.com/SunWeb3Sec/DeFiHackLabs/main/past/2021/README.md",
}

# Curated foundational 2020 DeFi hacks
HISTORICAL_2020_INCIDENTS = [
    {
        "date": "2020-04-18",
        "protocol": "Lendf.Me",
        "description": "ERC777 hook reentrancy exploit on dForce Lendf.Me draining supply pools",
        "loss_usd": 25_000_000.0,
        "attack_type": "REENTRANCY",
        "poc": "src/test/2020-04/LendfMe_exp.sol",
    },
    {
        "date": "2020-04-18",
        "protocol": "Uniswap v1",
        "description": "imBTC ERC777 tokensReceived reentrancy draining ETH liquidity pool",
        "loss_usd": 300_000.0,
        "attack_type": "REENTRANCY",
        "poc": "src/test/2020-04/uniswap-erc777.sol",
    },
    {
        "date": "2020-06-28",
        "protocol": "Balancer",
        "description": "STA token deflationary transfer fee flash loan price manipulation",
        "loss_usd": 500_000.0,
        "attack_type": "FLASH_LOAN_MANIPULATION",
        "poc": "src/test/2020-06/Balancer_20200628_exp.sol",
    },
    {
        "date": "2020-06-18",
        "protocol": "Bancor",
        "description": "Safe transferFrom missing authorization flaw in BancorConverter v0.6",
        "loss_usd": 135_000.0,
        "attack_type": "ACCESS_CONTROL",
        "poc": "src/test/2020-06/Bancor_exp.sol",
    },
    {
        "date": "2020-08-04",
        "protocol": "Opyn",
        "description": "Double-spend exercise flaw in Opyn oTokens allowing collateral drain without burning",
        "loss_usd": 371_000.0,
        "attack_type": "LOGIC_ERROR",
        "poc": "src/test/2020-08/Opyn_exp.sol",
    },
    {
        "date": "2020-09-14",
        "protocol": "bZx",
        "description": "iToken transferFrom duplicate internal mint balance manipulation exploit",
        "loss_usd": 8_000_000.0,
        "attack_type": "LOGIC_ERROR",
        "poc": "src/test/2020-09/bzx_exp.sol",
    },
    {
        "date": "2020-10-26",
        "protocol": "Harvest Finance",
        "description": "Curve Y pool arbitrage and USDT/USDC vault share manipulation via flash loan",
        "loss_usd": 33_800_000.0,
        "attack_type": "ORACLE_MANIPULATION",
        "poc": "src/test/2020-10/HarvestFinance_exp.sol",
    },
    {
        "date": "2020-11-21",
        "protocol": "Pickle Finance",
        "description": "Arbitrary swapExactJarForJar execution flaw in Pickle Jar swapController",
        "loss_usd": 19_700_000.0,
        "attack_type": "ARBITRARY_EXECUTION",
        "poc": "src/test/2020-11/Pickle_exp.sol",
    },
    {
        "date": "2020-12-28",
        "protocol": "Cover Protocol",
        "description": "Blacksmith claimRewards infinite mint flaw in unshielded liquidity pool token rewarder",
        "loss_usd": 4_000_000.0,
        "attack_type": "REWARD_CALCULATION",
        "poc": "src/test/2020-12/Cover_exp.sol",
    },
]


def parse_loss_string(loss_str: Optional[str]) -> Optional[float]:
    """Parse text representations of losses into float USD values."""
    if not loss_str or "unknown" in loss_str.lower():
        return None

    s = loss_str.replace(",", "").replace("~", "").strip()

    # Millions: e.g. $8.2 million, $1.5M, 1.5 million, $30M
    m_mil = re.search(r"\$?([0-9.]+)\s*(?:million|m\b|mil\b)", s, re.IGNORECASE)
    if m_mil:
        try:
            return float(m_mil.group(1)) * 1_000_000.0
        except ValueError:
            pass

    # Thousands: e.g. $170k, 76k, $500 thousand
    m_k = re.search(r"\$?([0-9.]+)\s*(?:k\b|thousand)", s, re.IGNORECASE)
    if m_k:
        try:
            return float(m_k.group(1)) * 1_000.0
        except ValueError:
            pass

    # Direct dollar amounts: e.g. $1450, $31000000
    m_dir = re.search(r"\$([0-9.]+)", s)
    if m_dir:
        try:
            return float(m_dir.group(1))
        except ValueError:
            pass

    # Crypto estimates: ETH, BNB
    m_eth = re.search(r"([0-9.]+)\s*ETH", s, re.IGNORECASE)
    if m_eth:
        try:
            return float(m_eth.group(1)) * 2500.0  # Normalized avg
        except ValueError:
            pass

    m_bnb = re.search(r"([0-9.]+)\s*BNB", s, re.IGNORECASE)
    if m_bnb:
        try:
            return float(m_bnb.group(1)) * 500.0
        except ValueError:
            pass

    return None


def classify_attack_type(description: str) -> str:
    """Classify the attack vector from description keywords."""
    d = description.lower()
    if "reentrancy" in d or "re-entrancy" in d:
        return "REENTRANCY"
    if "oracle" in d or "price manipulation" in d:
        return "ORACLE_MANIPULATION"
    if "flashloan" in d or "flash loan" in d:
        return "FLASH_LOAN_MANIPULATION"
    if "access control" in d or "permissionless" in d or "privilege" in d or "missing caller" in d:
        return "ACCESS_CONTROL"
    if "arbitrary" in d or "delegatecall" in d:
        return "ARBITRARY_EXECUTION"
    if "signature" in d or "replay" in d or "permit" in d:
        return "SIGNATURE_REPLAY"
    if "rounding" in d or "precision" in d or "calculation" in d:
        return "ROUNDING_ERROR"
    if "invariant" in d or "accounting" in d or "denomination" in d:
        return "INSUFFICIENT_VALIDATION"
    if "transient storage" in d or "storage collision" in d:
        return "STORAGE_COLLISION"
    return "UNKNOWN"


def fetch_and_parse_year(year: str, url: str) -> List[Dict[str, Any]]:
    """Fetch and parse a year's markdown README from DeFiHackLabs."""
    incidents = []
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        logger.warning(f"Could not fetch {year} from {url}: {e}")
        return []

    # Split into incident sections based on ### YYYYMMDD
    blocks = re.split(r"(?=###\s+\d{8})", text)
    pattern = re.compile(r"###\s+(\d{4})(\d{2})(\d{2})\s*(?:-\s*)?([^-]+)\s*-\s*([^\n]+)")

    for block in blocks:
        m = pattern.search(block)
        if not m:
            continue
        yr, mo, da, proto_raw, desc_raw = m.groups()
        protocol = proto_raw.strip()
        description = desc_raw.strip()

        # Extract loss
        loss_m = re.search(r"Lost:\s*([^\n]+)", block)
        loss_text = loss_m.group(1).strip() if loss_m else None
        loss_usd = parse_loss_string(loss_text)

        # Extract PoC file or forge test command
        poc_m = re.search(r"forge test[^\n]+", block)
        poc_cmd = poc_m.group(0).strip() if poc_m else None
        poc_file_m = re.search(r"\[([^\]]+\.sol)\]\(([^)]+)\)", block)
        poc_file = poc_file_m.group(2).strip() if poc_file_m else None

        incidents.append({
            "date": f"{yr}-{mo}-{da}",
            "year": yr,
            "protocol": protocol,
            "description": description,
            "loss_usd": loss_usd,
            "attack_type": classify_attack_type(description),
            "poc_cmd": poc_cmd,
            "poc_file": poc_file,
            "raw_block": block[:400].strip(),
        })

    logger.info(f"Parsed {len(incidents)} incidents for {year} from DeFiHackLabs")
    return incidents


class HistoricalBackfillManager:
    """Manages ingestion of 2020–2026 historical exploit records into SQLite & archives."""

    def __init__(self, db: Database):
        self.db = db

    async def run_backfill(self) -> Dict[str, Any]:
        """Execute complete historical backfill into the local database."""
        logger.info("Starting comprehensive Web3 historical backfill (2020-2026)...")

        # 1. Ensure source exists
        from app.models.schemas import SourceConfig
        source_cfg = SourceConfig(
            name=HISTORICAL_SOURCE_NAME,
            url=HISTORICAL_SOURCE_URL,
            source_type=SourceType.SECURITY_COMPANY,
            collector_type="rss",
            reliability_score=95,
        )
        source_id = await self.db.upsert_source(source_cfg)

        all_incidents: List[Dict[str, Any]] = []

        # Add 2020 incidents
        for inc20 in HISTORICAL_2020_INCIDENTS:
            all_incidents.append({
                "date": inc20["date"],
                "year": "2020",
                "protocol": inc20["protocol"],
                "description": inc20["description"],
                "loss_usd": inc20["loss_usd"],
                "attack_type": inc20["attack_type"],
                "poc_cmd": f"forge test --contracts {inc20['poc']} -vvv",
                "poc_file": inc20["poc"],
                "raw_block": inc20["description"],
            })

        # Fetch 2021 through 2026
        for year, url in YEAR_URLS.items():
            parsed = await asyncio.to_thread(fetch_and_parse_year, year, url)
            all_incidents.extend(parsed)

        logger.info(f"Total historical incidents ready for ingestion: {len(all_incidents)}")

        inserted_articles = 0
        inserted_incidents = 0

        for inc in all_incidents:
            date_str = inc["date"]
            proto = inc["protocol"]
            desc = inc["description"]
            loss = inc.get("loss_usd")
            attack = inc.get("attack_type") or "UNKNOWN"
            poc_cmd = inc.get("poc_cmd") or ""
            poc_file = inc.get("poc_file") or ""

            # Construct canonical URL
            clean_proto = "".join(c for c in proto.lower() if c.isalnum() or c == "_")
            canonical_url = f"https://github.com/SunWeb3Sec/DeFiHackLabs/tree/main/{poc_file or f'past/{date_str}_{clean_proto}'}"
            url_hash = hashlib.sha256(canonical_url.encode()).hexdigest()

            # Check if article already exists
            cursor = await self.db.conn.execute("SELECT id, incident_id FROM articles WHERE url_hash = ?", (url_hash,))
            existing = await cursor.fetchone()

            published_iso = f"{date_str}T12:00:00Z"
            severity = "CRITICAL" if (loss and loss >= 1_000_000.0) else "HIGH"

            # Create or find incident
            incident_id = None
            if existing:
                incident_id = existing[1]
            else:
                # Check for existing incident matching protocol and date
                cur_inc = await self.db.conn.execute(
                    "SELECT id FROM incidents WHERE protocol = ? AND first_seen_at LIKE ?",
                    (proto, f"{date_str[:7]}%"),
                )
                inc_row = await cur_inc.fetchone()
                if inc_row:
                    incident_id = inc_row[0]
                else:
                    # Create new incident record
                    title_text = f"{proto} Incident: {desc[:90]}"
                    incident_id = await self.db.create_incident(
                        title=title_text,
                        protocol=proto,
                        chain=["Ethereum"],
                        attack_type=[attack],
                        estimated_loss_usd=loss,
                        severity=severity,
                        status="mitigated",
                    )
                    # Set the exact historical date for first_seen_at & last_updated_at
                    await self.db.conn.execute(
                        "UPDATE incidents SET first_seen_at = ?, last_updated_at = ? WHERE id = ?",
                        (published_iso, published_iso, incident_id),
                    )
                    inserted_incidents += 1

                # Insert into articles
                content_body = (
                    f"## {proto} Incident Analysis\n\n"
                    f"**Date:** {date_str}\n"
                    f"**Loss:** ${loss:,.0f} USD\n" if loss else "**Loss:** Undisclosed\n"
                    f"**Vector:** {attack}\n"
                    f"**Description:** {desc}\n\n"
                    f"### Reproduction\n```sh\n{poc_cmd}\n```\n"
                )

                cursor = await self.db.conn.execute(
                    """
                    INSERT INTO articles (
                        url, url_hash, title, content, summary, published_at,
                        first_seen_at, source_id, category, severity,
                        attack_type, estimated_loss_usd, protocol, chain,
                        security_relevance, confidence, incident_id, classified_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                    """,
                    (
                        canonical_url,
                        url_hash,
                        f"{proto} Exploit: {desc[:80]}",
                        content_body,
                        desc,
                        published_iso,
                        published_iso,
                        source_id,
                        "CRITICAL_SECURITY" if severity == "CRITICAL" else "HIGH_SECURITY",
                        severity,
                        json.dumps([attack]),
                        loss,
                        proto,
                        json.dumps(["Ethereum"]),
                        95,
                        90,
                        incident_id,
                    ),
                )
                inserted_articles += 1

        await self.db.conn.commit()

        # Update dual knowledge archives on disk
        from app.processing.archive import ArchiveManager
        archive_mgr = ArchiveManager()
        archive_res = await archive_mgr.backfill_archives(self.db)

        logger.info(
            f"[OK] Historical backfill complete! "
            f"Inserted {inserted_articles} articles, {inserted_incidents} incidents. "
            f"Total security archive: {archive_res['security_count']} records."
        )

        return {
            "total_parsed": len(all_incidents),
            "inserted_articles": inserted_articles,
            "inserted_incidents": inserted_incidents,
            "archive_security_count": archive_res["security_count"],
        }
