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
    template_name: str | None = None
    template_version: str | None = None
    engineer_name: str | None = None
    template_rules: list[TemplateRule] | None = None
    quick_pass: bool = False
    snippet_mode: bool | None = None  # None = auto-detect
    context_hint: str | None = None  # e.g. "interface", "bgp_neighbor"


class CompareRequest(BaseModel):
    """Running vs. startup config comparison."""
    running_config: str = Field(..., min_length=1, max_length=500_000)
    startup_config: str = Field(..., min_length=1, max_length=500_000)
    vendor: Vendor | None = None


class CrossConfigInput(BaseModel):
    config_text: str = Field(..., min_length=1, max_length=500_000)
    vendor: Vendor | None = None
    hostname: str | None = None


class CrossConfigRequest(BaseModel):
    configs: list[CrossConfigInput] = Field(..., min_length=2, max_length=10)


class BatchReviewRequest(BaseModel):
    zip_filename: str | None = None
    zip_base64: str = Field(..., min_length=1)
    vendor: Vendor | None = None
    engineer_name: str | None = None
    quick_pass: bool = False
    snippet_mode: bool | None = None
    context_hint: str | None = None
    template_id: str | None = None
    template_name: str | None = None
    template_version: str | None = None
    template_rules: list[TemplateRule] | None = None


class NLQueryRequest(BaseModel):
    config_text: str = Field(..., min_length=1, max_length=500_000)
    question: str = Field(..., min_length=1, max_length=2000)
    vendor: Vendor | None = None


class MultiConfigQueryItem(BaseModel):
    config_text: str = Field(..., min_length=1, max_length=500_000)
    vendor: Vendor | None = None
    hostname: str | None = None


class MultiConfigQueryRequest(BaseModel):
    configs: list[MultiConfigQueryItem] = Field(..., min_length=2, max_length=10)
    question: str = Field(..., min_length=1, max_length=2000)


class PipelineReviewRequest(AnalyzeRequest):
    fail_on_severity: Severity = Severity.CRITICAL
    max_blocking_findings: int | None = Field(default=None, ge=1)
    include_review: bool = True
    webhook_url: str | None = None
    webhook_headers: dict[str, str] = Field(default_factory=dict)


class IntegrationTarget(str, Enum):
    SERVICENOW = "servicenow"
    JIRA = "jira"
    WEBHOOK = "webhook"


class IntegrationAuthType(str, Enum):
    BASIC = "basic"
    BEARER = "bearer"


class IntegrationAuth(BaseModel):
    auth_type: IntegrationAuthType = IntegrationAuthType.BEARER
    username: str | None = None
    password: str | None = None
    token: str | None = None


class ServiceNowExportOptions(BaseModel):
    instance_url: str
    table_name: str = "change_request"
    record_sys_id: str
    update_work_notes: bool = True
    update_short_description: bool = False


class JiraExportOptions(BaseModel):
    base_url: str
    issue_key: str
    add_comment: bool = True


class WebhookExportOptions(BaseModel):
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    include_review_payload: bool = True
    embed_artifacts: bool = False


class ReviewExportRequest(AnalyzeRequest):
    target: IntegrationTarget
    auth: IntegrationAuth | None = None
    service_now: ServiceNowExportOptions | None = None
    jira: JiraExportOptions | None = None
    webhook: WebhookExportOptions | None = None
    include_pdf: bool = True
    include_json: bool = True
    include_html: bool = False
    export_comment: str | None = None
    attachment_prefix: str = "config-studio-review"
    metadata: dict[str, str] = Field(default_factory=dict)


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


class ReviewSummary(BaseModel):
    total_findings: int
    critical_count: int
    warning_count: int
    info_count: int
    categories: dict[str, int] = Field(default_factory=dict)  # category -> count


class ReportHeader(BaseModel):
    generated_at_utc: str
    engineer_identity: str
    config_hash: str
    template_version_used: str
    platform_detected: str
    hostname: str | None = None


class ExecutiveSummary(BaseModel):
    pass_fail: bool
    pass_fail_label: str
    risk_score: int
    risk_grade: str
    finding_counts: dict[str, int] = Field(default_factory=dict)
    benchmark_label: str


class TemplateComplianceItem(BaseModel):
    rule_name: str
    severity: Severity
    status: str
    description: str


class TemplateComplianceSummary(BaseModel):
    template_name: str
    template_version: str
    passed_rules: int
    failed_rules: int
    deviations: list[TemplateComplianceItem] = Field(default_factory=list)


class OrderedChangeScript(BaseModel):
    generated: bool = False
    rationale: str | None = None
    apply_script: str = ""
    rollback_script: str = ""
    finding_order: list[str] = Field(default_factory=list)


class ReportBody(BaseModel):
    executive_summary: ExecutiveSummary
    findings_detail: list[Finding]
    template_compliance: TemplateComplianceSummary
    ordered_change_script: OrderedChangeScript | None = None
    config_diff: dict | None = None


class ReviewReport(BaseModel):
    review_id: str
    format: str = "json"
    header: ReportHeader
    body: ReportBody


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
    report: ReviewReport


class CompareResponse(BaseModel):
    lost_on_reload: list[Finding]
    added_since_startup: list[dict]
    removed_since_startup: list[dict]


class CrossConfigResponse(BaseModel):
    findings: list[Finding]
    inferred_links: list[dict] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)


class BatchArchiveSkippedEntry(BaseModel):
    filename: str
    reason: str


class BatchArchiveSummary(BaseModel):
    zip_filename: str | None = None
    archive_member_count: int = 0
    readable_config_count: int = 0
    skipped_directory_count: int = 0
    skipped_non_config_count: int = 0
    skipped_empty_count: int = 0
    skipped_undecodable_count: int = 0
    extracted_text_bytes: int = 0
    skipped_entries: list[BatchArchiveSkippedEntry] = Field(default_factory=list)


class BatchReviewItem(BaseModel):
    filename: str
    config_text: str
    review: AnalyzeResponse


class BatchReviewResponse(BaseModel):
    review_count: int
    filenames: list[str] = Field(default_factory=list)
    reviews: list[BatchReviewItem] = Field(default_factory=list)
    archive_summary: BatchArchiveSummary | None = None
    cross_config: CrossConfigResponse | None = None
    summary: dict[str, int] = Field(default_factory=dict)


class NLQueryResponse(BaseModel):
    answer: str
    line_references: list[int] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


class MultiConfigQueryMatch(BaseModel):
    hostname: str
    vendor: str
    line_references: list[int] = Field(default_factory=list)
    preview: list[str] = Field(default_factory=list)


class MultiConfigQueryResponse(BaseModel):
    answer: str
    matches: list[MultiConfigQueryMatch] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)


class PipelineReviewResponse(BaseModel):
    gate_status: str
    should_block: bool
    fail_on_severity: Severity
    blocking_findings_count: int
    max_blocking_findings: int | None = None
    blocking_findings: list[Finding] = Field(default_factory=list)
    summary: dict[str, int | str | bool] = Field(default_factory=dict)
    review: AnalyzeResponse | None = None
    webhook: dict[str, str | bool | int | None] = Field(default_factory=dict)


class ReviewExportResponse(BaseModel):
    target: IntegrationTarget
    review_id: str
    destination: dict[str, str] = Field(default_factory=dict)
    attachments: list[dict[str, str | int]] = Field(default_factory=list)
    comment: dict[str, str | bool | int | None] = Field(default_factory=dict)
    delivery: dict[str, str | bool | int | None] = Field(default_factory=dict)
    summary: dict[str, str | int | bool] = Field(default_factory=dict)
    review: AnalyzeResponse
