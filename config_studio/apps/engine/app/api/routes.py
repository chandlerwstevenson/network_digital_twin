"""API routes for the analysis engine."""

from __future__ import annotations

import hashlib
import uuid

from fastapi import APIRouter, HTTPException, Header

from app.api.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    CompareRequest,
    CompareResponse,
    NLQueryRequest,
    NLQueryResponse,
    VendorDetection,
    ReviewStatus,
    SnippetInfo,
    RiskScore,
    ReviewSummary,
)
from app.config import ENGINE_API_KEY
from app.parsers.detector import detect_vendor
from app.snippet.detector import detect_snippet
from app.linters.syntax import SyntaxLinter
from app.linters.semantic import SemanticLinter
from app.linters.security import SecurityLinter
from app.linters.compliance import ComplianceTagger
from app.templates.engine import TemplateEngine
from app.remediation.generator import RemediationGenerator
from app.scoring.risk import calculate_risk_score
from app.query.nl_engine import answer_query

router = APIRouter()


def _verify_key(x_api_key: str = Header(None)):
    """Verify engine API key for internal calls."""
    if ENGINE_API_KEY and x_api_key != ENGINE_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid engine API key")


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_config(req: AnalyzeRequest, _=Header(None, alias="x-api-key")):
    """Run full config analysis: parse, lint, check security, score."""
    review_id = str(uuid.uuid4())
    config_hash = hashlib.sha256(req.config_text.encode()).hexdigest()

    # 1. Vendor detection
    if req.vendor:
        vendor_info = VendorDetection(
            vendor=req.vendor,
            os_version=req.os_version,
            confidence=1.0,
        )
    else:
        vendor_info = detect_vendor(req.config_text)

    # 2. Snippet detection
    if req.snippet_mode is not None:
        snippet_info = SnippetInfo(is_snippet=req.snippet_mode, detected_section=req.context_hint)
    else:
        snippet_info = detect_snippet(req.config_text, req.context_hint)

    # 3. Run linters
    lines = req.config_text.splitlines()
    findings = []

    syntax_linter = SyntaxLinter(vendor_info.vendor, vendor_info.os_version)
    findings.extend(syntax_linter.lint(lines))

    semantic_linter = SemanticLinter(vendor_info.vendor)
    findings.extend(semantic_linter.lint(lines))

    security_linter = SecurityLinter(vendor_info.vendor)
    findings.extend(security_linter.lint(lines))

    # 4. Template checks
    if req.template_rules:
        template_engine = TemplateEngine()
        findings.extend(template_engine.check(lines, req.template_rules, vendor_info.vendor))

    # 5. Compliance tagging
    tagger = ComplianceTagger()
    findings = tagger.tag_findings(findings)

    # 6. Generate remediation + rollback for findings that don't have them yet
    remediator = RemediationGenerator(vendor_info.vendor)
    findings = remediator.enrich(findings, lines)

    # 7. Snippet suppression — remove findings that require global context
    if snippet_info.is_snippet:
        original_count = len(findings)
        findings = [f for f in findings if f.category.value != "compliance" or "global" not in f.description.lower()]
        snippet_info.suppressed_checks = [
            f"Suppressed {original_count - len(findings)} global-context checks in snippet mode"
        ] if original_count > len(findings) else []

    # 8. Quick-pass filter
    if req.quick_pass:
        findings = [f for f in findings if f.severity.value == "critical"]

    # 9. Risk score
    risk_score = calculate_risk_score(findings, snippet_info.is_snippet)

    # 10. Summary
    critical_count = sum(1 for f in findings if f.severity.value == "critical")
    warning_count = sum(1 for f in findings if f.severity.value == "warning")
    info_count = sum(1 for f in findings if f.severity.value == "info")
    categories = {}
    for f in findings:
        categories[f.category.value] = categories.get(f.category.value, 0) + 1

    summary = ReviewSummary(
        total_findings=len(findings),
        critical_count=critical_count,
        warning_count=warning_count,
        info_count=info_count,
        categories=categories,
    )

    return AnalyzeResponse(
        review_id=review_id,
        status=ReviewStatus.COMPLETE,
        vendor=vendor_info,
        snippet_info=snippet_info,
        findings=findings,
        risk_score=risk_score,
        pass_fail=critical_count == 0,
        summary=summary,
        config_hash=config_hash,
    )


@router.post("/compare", response_model=CompareResponse)
async def compare_configs(req: CompareRequest):
    """Compare running vs. startup config — flag 'lost on reload' commands."""
    vendor_info = detect_vendor(req.running_config) if not req.vendor else VendorDetection(
        vendor=req.vendor, confidence=1.0
    )

    running_lines = set(req.running_config.strip().splitlines())
    startup_lines = set(req.startup_config.strip().splitlines())

    lost_on_reload = running_lines - startup_lines
    added_since = startup_lines - running_lines

    from app.api.schemas import Finding, Severity, FindingCategory

    lost_findings = []
    for i, line in enumerate(req.running_config.splitlines()):
        stripped = line.strip()
        if stripped and stripped in lost_on_reload and not stripped.startswith("!"):
            lost_findings.append(Finding(
                id=str(uuid.uuid4()),
                line_start=i + 1,
                line_end=i + 1,
                severity=Severity.CRITICAL,
                category=FindingCategory.BEST_PRACTICE,
                title="Command lost on reload",
                description=f"This command is in running-config but not startup-config. "
                            f"It will be lost on device reload: '{stripped}'",
                remediation=f"copy running-config startup-config\n! Or: write memory",
                rollback="! No rollback needed — this preserves current state",
                compliance_tags=["operational-risk"],
            ))

    return CompareResponse(
        lost_on_reload=lost_findings,
        added_since_startup=[{"line": l} for l in added_since if l.strip() and not l.strip().startswith("!")],
        removed_since_startup=[{"line": l} for l in lost_on_reload if l.strip() and not l.strip().startswith("!")],
    )


@router.post("/query", response_model=NLQueryResponse)
async def query_config(req: NLQueryRequest):
    """Natural language query against a config using Claude API."""
    vendor_info = detect_vendor(req.config_text) if not req.vendor else VendorDetection(
        vendor=req.vendor, confidence=1.0
    )
    return await answer_query(req.config_text, req.question, vendor_info)
