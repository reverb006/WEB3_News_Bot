"""
Source Registry — all data sources the radar monitors.

This is the single place where sources are defined. Adding a new source
is as simple as adding a new SourceConfig to the SOURCES list.

Sources are organized by reliability tier:
  Tier 1 (80-100): Incident databases, primary protocol sources
  Tier 2 (60-79):  Security companies, audit firms, bug bounty platforms
  Tier 3 (40-59):  Protocol ecosystem blogs
  Tier 4 (20-39):  News media outlets

Every RSS URL in this file was verified with a live HTTP request
on September 22, 2026. If a feed stops working, set is_active=False
and check the URL — don't delete the entry.
"""

from app.models.schemas import SourceConfig, SourceType

# ============================================================
# All verified sources
# ============================================================

SOURCES: list[SourceConfig] = [
    # --------------------------------------------------------
    # TIER 2: Security Companies & Audit Firms (RSS)
    # --------------------------------------------------------
    SourceConfig(
        name="Trail of Bits",
        url="https://blog.trailofbits.com/feed/",
        source_type=SourceType.SECURITY_COMPANY,
        collector_type="rss",
        reliability_score=85,
        # World-class security firm. Posts deep technical research on
        # smart contracts, cryptography, and program analysis.
    ),
    SourceConfig(
        name="Chainalysis",
        url="https://www.chainalysis.com/blog/feed/",
        source_type=SourceType.SECURITY_COMPANY,
        collector_type="rss",
        reliability_score=80,
        # Leading blockchain analytics company. Publishes data-driven
        # reports on hacks, ransomware, and illicit crypto flows.
    ),
    SourceConfig(
        name="PeckShield",
        url="https://medium.com/feed/@peckshield",
        source_type=SourceType.SECURITY_COMPANY,
        collector_type="rss",
        reliability_score=75,
        # Prominent blockchain security auditor. Frequently first to
        # report exploits and post-mortems on Medium.
    ),
    SourceConfig(
        name="Immunefi",
        url="https://medium.com/feed/immunefi",
        source_type=SourceType.BUG_BOUNTY_PLATFORM,
        collector_type="rss",
        reliability_score=80,
        # Largest Web3 bug bounty platform. Publishes vulnerability
        # disclosures, post-mortems, and security research.
    ),
    SourceConfig(
        name="SlowMist",
        url="https://medium.com/feed/@slowmist",
        source_type=SourceType.SECURITY_COMPANY,
        collector_type="rss",
        reliability_score=85,
        # Elite blockchain security auditor & threat intelligence firm.
        # Publishes vulnerability writeups, hack post-mortems, and exploit tracking.
    ),

    # --------------------------------------------------------
    # TIER 3: Protocol & Ecosystem Blogs (RSS)
    # --------------------------------------------------------
    SourceConfig(
        name="Ethereum Foundation",
        url="https://blog.ethereum.org/feed.xml",
        source_type=SourceType.PRIMARY_SOURCE,
        collector_type="rss",
        reliability_score=95,
        # Official Ethereum blog. Security advisories, protocol upgrades,
        # and EIP announcements come from here.
    ),
    SourceConfig(
        name="Chainlink",
        url="https://blog.chain.link/rss/",
        source_type=SourceType.PRIMARY_SOURCE,
        collector_type="rss",
        reliability_score=85,
        is_active=False,  # Deprecated: Chainlink migrated blog to HTML-only Webflow without RSS XML
    ),

    # --------------------------------------------------------
    # TIER 4: News Media (RSS)
    # --------------------------------------------------------
    SourceConfig(
        name="The Defiant",
        url="https://thedefiant.io/feed",
        source_type=SourceType.NEWS_MEDIA,
        collector_type="rss",
        reliability_score=50,
        max_items=25,
        # Major DeFi news platform covering smart contract updates, security disclosures, and market events.
    ),
    SourceConfig(
        name="Cointelegraph",
        url="https://cointelegraph.com/rss",
        source_type=SourceType.NEWS_MEDIA,
        collector_type="rss",
        reliability_score=40,
        max_items=30,  # They publish a LOT; limit to recent items
        # Major crypto news outlet. High volume, mixes security with
        # market news. Useful for catching breaking hack reports early.
    ),
    SourceConfig(
        name="CoinDesk",
        url="https://www.coindesk.com/arc/outboundfeeds/rss/?outputType=xml",
        source_type=SourceType.NEWS_MEDIA,
        collector_type="rss",
        reliability_score=45,
        max_items=30,
        # Established crypto news. Better editorial quality than most,
        # but still mixes security with market/price content.
    ),
]


def get_active_sources(collector_type: str | None = None) -> list[SourceConfig]:
    """
    Get all active sources, optionally filtered by collector type.

    Args:
        collector_type: Filter by "rss", "defi_rekt", etc. None = all types.

    Returns:
        List of active SourceConfig objects.
    """
    sources = [s for s in SOURCES if s.is_active]
    if collector_type:
        sources = [s for s in sources if s.collector_type == collector_type]
    return sources
