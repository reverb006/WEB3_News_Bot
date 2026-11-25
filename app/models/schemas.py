"""
Pydantic schemas — the data models that flow through the entire pipeline.

These models define the shape of data at every stage:
  RawArticle    → what a collector produces (unclassified)
  Classification → what Gemini returns (structured JSON)
  ClassifiedArticle → RawArticle + Classification merged
  SourceConfig  → definition of a single feed/API source

Why Pydantic?
  1. Validates data automatically (bad RSS won't crash us)
  2. Gemini SDK uses Pydantic models for structured output
  3. Serializes cleanly to/from JSON and SQLite
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator


# ============================================================
# Enums — used for both classification and database storage
# ============================================================

class Category(str, Enum):
    """Security-relevance categories assigned by Gemini."""
    CRITICAL_SECURITY = "CRITICAL_SECURITY"
    HIGH_SECURITY = "HIGH_SECURITY"
    SECURITY_RESEARCH = "SECURITY_RESEARCH"
    PROTOCOL_UPDATE = "PROTOCOL_UPDATE"
    MAJOR_WEB3_NEWS = "MAJOR_WEB3_NEWS"
    REGULATION = "REGULATION"
    MARKET = "MARKET"
    LOW_VALUE = "LOW_VALUE"
    IGNORE = "IGNORE"


class Severity(str, Enum):
    """How severe is the security impact."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    NONE = "NONE"


class AttackType(str, Enum):
    """Known attack/vulnerability categories."""
    REENTRANCY = "REENTRANCY"
    ORACLE_MANIPULATION = "ORACLE_MANIPULATION"
    FLASH_LOAN = "FLASH_LOAN"
    ACCESS_CONTROL = "ACCESS_CONTROL"
    PRIVATE_KEY_COMPROMISE = "PRIVATE_KEY_COMPROMISE"
    SIGNATURE_VALIDATION = "SIGNATURE_VALIDATION"
    BRIDGE = "BRIDGE"
    PROXY = "PROXY"
    UPGRADEABILITY = "UPGRADEABILITY"
    PRICE_MANIPULATION = "PRICE_MANIPULATION"
    LOGIC_ERROR = "LOGIC_ERROR"
    ARITHMETIC = "ARITHMETIC"
    VALIDATION_BYPASS = "VALIDATION_BYPASS"
    CROSS_CHAIN = "CROSS_CHAIN"
    GOVERNANCE = "GOVERNANCE"
    PHISHING = "PHISHING"
    RUGPULL = "RUGPULL"
    UNKNOWN = "UNKNOWN"
    OTHER = "OTHER"


class IncidentStatus(str, Enum):
    """Current status of a security incident."""
    ACTIVE = "active"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    UNKNOWN = "unknown"


class SourceType(str, Enum):
    """Reliability tier of the information source."""
    PRIMARY_SOURCE = "PRIMARY_SOURCE"          # Official protocol announcements
    SECURITY_COMPANY = "SECURITY_COMPANY"      # Trail of Bits, PeckShield, etc.
    BUG_BOUNTY_PLATFORM = "BUG_BOUNTY_PLATFORM"  # Immunefi, etc.
    SECURITY_RESEARCHER = "SECURITY_RESEARCHER"
    NEWS_MEDIA = "NEWS_MEDIA"                  # CoinDesk, Cointelegraph
    SOCIAL_MEDIA = "SOCIAL_MEDIA"
    INCIDENT_DATABASE = "INCIDENT_DATABASE"    # De.Fi REKT, etc.
    UNKNOWN = "UNKNOWN"


class AlertStatus(str, Enum):
    """Telegram alert delivery status."""
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"


# ============================================================
# Source Configuration
# ============================================================

class SourceConfig(BaseModel):
    """
    Configuration for a single data source.

    This is NOT a database record — it's the static config that tells
    the collectors what to fetch. Defined in source_registry.py.
    """
    name: str = Field(description="Human-readable source name")
    url: str = Field(description="Feed URL or API endpoint")
    source_type: SourceType
    collector_type: str = Field(description="Which collector handles this: 'rss' or 'defi_rekt'")
    reliability_score: int = Field(
        default=50, ge=0, le=100,
        description="How much we trust this source (0=untrusted, 100=official)"
    )
    is_active: bool = Field(default=True, description="Whether to collect from this source")
    # RSS-specific
    max_items: int = Field(default=50, description="Max items to process per fetch")


# ============================================================
# Pipeline Data Models
# ============================================================

class RawArticle(BaseModel):
    """
    A single item collected from any source, before AI classification.

    This is the universal format that every collector must produce.
    It holds the raw data; classification fields are filled later.
    """
    url: str = Field(description="Canonical URL of the article/post")
    title: str = Field(description="Article title, cleaned of HTML")
    content: str = Field(default="", description="Full text or description, cleaned of HTML")
    published_at: Optional[datetime] = Field(
        default=None, description="When the source says it was published"
    )
    source_name: str = Field(description="Name of the source (matches SourceConfig.name)")
    source_type: SourceType = Field(description="Reliability tier of the source")
    source_reliability: int = Field(
        default=50, ge=0, le=100,
        description="Reliability score of the source"
    )

    @field_validator("title")
    @classmethod
    def title_not_empty(cls, v: str) -> str:
        """Reject articles with blank titles — they're useless."""
        stripped = v.strip()
        if not stripped:
            raise ValueError("Article title cannot be empty")
        return stripped

    @field_validator("url")
    @classmethod
    def url_looks_valid(cls, v: str) -> str:
        """Basic URL validation — must start with http(s)."""
        stripped = v.strip()
        if not stripped.startswith(("http://", "https://")):
            raise ValueError(f"URL must start with http:// or https://, got: {stripped[:50]}")
        return stripped


class Classification(BaseModel):
    """
    Structured classification returned by Gemini.

    This exact model is passed to the Gemini SDK as `response_schema`,
    so the AI is forced to return data matching this shape.
    """
    title: str = Field(description="Cleaned/improved title")
    summary: str = Field(description="2-4 sentence summary of the item")
    category: Category = Field(description="Security-relevance category")
    severity: Severity = Field(description="Security severity level")
    security_relevance: int = Field(
        ge=0, le=100,
        description="How relevant to smart-contract security (0=irrelevant, 100=critical)"
    )
    confidence: int = Field(
        ge=0, le=100,
        description="How confident the AI is in this classification (0=guessing, 100=certain)"
    )
    estimated_loss_usd: Optional[float] = Field(
        default=None,
        description="Estimated financial loss in USD. null if unknown or not applicable."
    )
    chain: list[str] = Field(
        default_factory=list,
        description="Affected blockchain(s), e.g. ['Ethereum', 'BSC']. Empty if unknown."
    )
    protocol: str = Field(
        default="",
        description="Affected protocol name. Empty if unknown or not applicable."
    )
    attack_type: list[AttackType] = Field(
        default_factory=list,
        description="Type(s) of attack or vulnerability. Use UNKNOWN if not established."
    )
    status: IncidentStatus = Field(
        default=IncidentStatus.UNKNOWN,
        description="Current incident status."
    )
    source_type: SourceType = Field(
        default=SourceType.UNKNOWN,
        description="How the AI perceives the source's reliability."
    )
    duplicate_of: Optional[str] = Field(
        default=None,
        description="URL of the original article if this is a duplicate. null if original."
    )
    should_alert: bool = Field(
        default=False,
        description="Whether this item warrants a real-time Telegram alert."
    )


class ClassifiedArticle(BaseModel):
    """
    An article that has passed through the full pipeline:
    collection → normalization → deduplication → classification → scoring.
    """
    # Original article data
    url: str
    title: str
    content: str
    published_at: Optional[datetime]
    first_seen_at: datetime
    source_name: str
    source_type: SourceType
    source_reliability: int

    # Classification (from Gemini)
    classification: Classification

    # Priority (computed after classification)
    priority_score: int = Field(default=0, ge=0, le=100)

    # Database tracking
    db_id: Optional[int] = Field(default=None, description="articles.id after insertion")
    incident_id: Optional[int] = Field(default=None, description="Linked incident ID")
    is_duplicate: bool = Field(default=False)


class DeepAnalysis(BaseModel):
    """
    In-depth smart-contract security case study generated by Gemini.
    """
    executive_summary: str = Field(description="2-3 sentence executive summary of the exploit")
    root_cause_analysis: str = Field(description="Deep dive into the specific flaw in contract logic, compiler, or mechanism")
    attack_vector_steps: list[str] = Field(description="Step-by-step breakdown of how the exploit was executed")
    vulnerable_components: list[str] = Field(description="Smart contract functions, libraries, or protocols involved")
    auditor_lessons: list[str] = Field(description="Actionable takeaways for auditors to identify similar vulnerabilities")
    mitigations_and_invariants: list[str] = Field(description="Recommended code fixes, security invariants, or Foundry/Slither tests")
    affected_ecosystems: list[str] = Field(default_factory=list, description="Chains or related protocols exposed to risk")


class DailyDigest(BaseModel):
    """
    Compiled 24-hour daily security digest model.
    """
    digest_date: str = Field(description="Date string for the digest (YYYY-MM-DD)")
    total_articles: int = Field(default=0, description="Total classified articles processed")
    total_incidents: int = Field(default=0, description="Total unique incidents tracked")
    total_loss_usd: float = Field(default=0.0, description="Total estimated financial loss across incidents")
    critical_exploits: list[dict] = Field(default_factory=list, description="Critical exploits and confirmed loss events")
    bug_bounties: list[dict] = Field(default_factory=list, description="Bug bounty payouts, programs, and disclosures")
    security_research: list[dict] = Field(default_factory=list, description="Deep security research, tooling, and audit analyses")
    protocol_updates: list[dict] = Field(default_factory=list, description="Major protocol upgrades, EIPs, and client releases")
    top_must_read: list[dict] = Field(default_factory=list, description="Top 5 highest priority items of the day")

