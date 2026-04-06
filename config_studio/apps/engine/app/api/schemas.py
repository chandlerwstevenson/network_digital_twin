"""Pydantic models for API request/response schemas."""

from __future__ import annotations

from enum import Enum
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Vendor(str, Enum):
    CISCO_IOS = "cisco_ios"
    CISCO_IOSXE = "cisco_iosxe"
    JUNOS = "junos"
    # v1.1
    CISCO_NXOS = "cisco_nxos"
    ARISTA_EOS = "arista_eos"
    PALO_ALTO = "palo_alto"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class FindingCategory(str, Enum):
    SYNTAX = "syntax"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    BEST_PRACTICE = "best_practice"


class ReviewStatus(str, Enum):
    PENDING = "pending"
    COMPLETE = "complete"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    config_text: str = Field(..., min_length=1, max_length=500_000)
    vendor: Vendor | None = None  # None = auto-detect
    os_version: str | None = None
    template_id: str | None = None
    template_rules: list[TemplateRule] | None = None
    quick_pass: bool = False
    snippet_mode: bool | None = None  # None = auto-detect
    context_hint: str | None = None  # e.g. "interface", "bgp_neighbor"


class CompareRequest(BaseModel):
    """Running vs. startup config comparison."""
    running_config: str = Field(..., min_length=1, max_length=500_000)
    startup_config: str = Field(..., min_length=1, max_length=500_000)
    vendor: Vendor | None = None


class NLQueryRequest(BaseModel):
    config_text: str = Field(..., min_length=1, max_length=500_000)
    question: str = Field(..., min_length=1, max_length=2000)
    vendor: Vendor | None = None


# ---------------------------------------------------------------------------
# Template models
# ---------------------------------------------------------------------------

class RuleType(str, Enum):
    REQUIRED_COMMAND = "required_command"
    BANNED_COMMAND = "banned_command"
    REQUIRED_VALUE = "required_value"
    NAMING_CONVENTION = "naming_convention"
    STRUCTURAL = "structural"


class TemplateRule(BaseModel):
    id: str | None = None
    name: str
    description: str
    rule_type: RuleType
    severity: Severity = Severity.WARNING
    # Rule-type-specific config
    pattern: str | None = None  # regex or glob pattern
    section: str | None = None  # config section scope (e.g. "interface", "router bgp")
    expected_value: str | None = None
    condition: str | None = None  # for structural rules


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class VendorDetection(BaseModel):
    vendor: Vendor
    os_version: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    hostname: str | None = None


class Finding(BaseModel):
    id: str
    line_start: int
    line_end: int
    severity: Severity
    category: FindingCategory
    title: str
    description: str
    remediation: str
    rollback: str
    reference_url: str | None = None
    compliance_tags: list[str] = Field(default_factory=list)
    config_context: str | None = None  # surrounding lines for context


class SnippetInfo(BaseModel):
    is_snippet: bool
    detected_section: str | None = None
    suppressed_checks: list[str] = Field(default_factory=list)
    external_references: list[str] = Field(default_factory=list)


class RiskScore(BaseModel):
    score: int = Field(ge=0, le=100)
    grade: str  # A-F
    benchmark_label: str  # e.g. "typical for mid-market pharma networks"
    breakdown: dict[str, int] = Field(default_factory=dict)  # category -> subscore


class AnalyzeResponse(BaseModel):
    review_id: str
    status: ReviewStatus
    vendor: VendorDetection
    snippet_info: SnippetInfo
    findings: list[Finding]
    risk_score: RiskScore
    pass_fail: bool  # True = PASS (no Critical findings)
    summary: ReviewSummary
    config_hash: str  # SHA-256


class ReviewSummary(BaseModel):
    total_findings: int
    critical_count: int
    warning_count: int
    info_count: int
    categories: dict[str, int] = Field(default_factory=dict)  # category -> count


class CompareResponse(BaseModel):
    lost_on_reload: list[Finding]
    added_since_startup: list[dict]
    removed_since_startup: list[dict]


class NLQueryResponse(BaseModel):
    answer: str
    line_references: list[int] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
