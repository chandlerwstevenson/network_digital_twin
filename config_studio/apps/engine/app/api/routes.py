"""API routes for the analysis engine."""

from __future__ import annotations

import base64
import hashlib
import io
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException, Header, Depends
from fastapi.responses import HTMLResponse, Response

from app.api.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    CompareRequest,
    CompareResponse,
    CrossConfigRequest,
    CrossConfigResponse,
    BatchReviewRequest,
    BatchReviewResponse,
    BatchReviewItem,
    NLQueryRequest,
    NLQueryResponse,
    MultiConfigQueryRequest,
    MultiConfigQueryResponse,
    VendorDetection,
    ReviewStatus,
    SnippetInfo,
    RiskScore,
    ReviewSummary,
    ReviewReport,
    ReportHeader,
    ReportBody,
    ExecutiveSummary,
    TemplateComplianceSummary,
    TemplateComplianceItem,
    OrderedChangeScript,
)
from app.config import ENGINE_API_KEY
from app.parsers.detector import detect_vendor
from app.snippet.detector import detect_snippet
from app.linters.syntax import SyntaxLinter
from app.linters.semantic import SemanticLinter
from app.linters.security import SecurityLinter
from app.linters.compliance import ComplianceTagger
from app.templates.engine import TemplateEngine
from app.templates.library import load_starter_templates, get_starter_template
from app.remediation.generator import RemediationGenerator
from app.scoring.risk import calculate_risk_score
from app.query.nl_engine import answer_query, answer_multi_config_query
from app.reporting import build_report_html, render_report_pdf_bytes
from app.correlation import correlate_configs

router = APIRouter()

ALLOWED_BATCH_EXTENSIONS = {".txt", ".conf", ".cfg", ".log", ".config", ".cnf", ".txt.bak"}


def _attach_context(findings, lines: list[str]):
    for finding in findings:
        if finding.config_context:
            continue
        start = max(finding.line_start - 2, 1)
        end = min(finding.line_end + 2, len(lines))
        snippet = []
        for idx in range(start, end + 1):
            snippet.append(f"L{idx}: {lines[idx - 1]}")
        finding.config_context = "\n".join(snippet)
    return findings


def _change_priority(finding) -> int:
    text = f"{finding.title} {finding.description} {finding.remediation}".lower()
    if any(token in text for token in ["route-map", "prefix-list", "community-list", "policy-map", "class-map"]):
        return 10
    if "vlan" in text and any(token in text for token in ["create", "define", "database"]):
        return 20
    if any(token in text for token in ["aaa", "tacacs", "radius", "snmp-server", "http", "https", "control-plane", "copp"]):
        return 30
    if any(token in text for token in ["interface", "router bgp", "router ospf", "line vty", "line con", "line aux"]):
        return 40
    return 50


def _dedupe_blocks(blocks: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for block in blocks:
        normalized = "\n".join(line.rstrip() for line in block.strip().splitlines()).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)
    return ordered


def _build_ordered_change_script(findings) -> OrderedChangeScript:
    actionable = [f for f in findings if (f.remediation or "").strip()]
    if not actionable:
        return OrderedChangeScript(generated=False, rationale="No actionable remediation blocks were generated from the current findings.")

    ordered_findings = sorted(actionable, key=lambda f: (_change_priority(f), f.line_start, f.title.lower()))
    remediation_blocks = _dedupe_blocks([f.remediation for f in ordered_findings if (f.remediation or "").strip()])
    rollback_blocks = _dedupe_blocks([f.rollback for f in reversed(ordered_findings) if (f.rollback or "").strip()])

    return OrderedChangeScript(
        generated=bool(remediation_blocks),
        rationale="Heuristic dependency ordering: define reusable objects and global policy before interface/protocol references; rollback is emitted in reverse order.",
        apply_script="\n\n".join(remediation_blocks),
        rollback_script="\n\n".join(rollback_blocks),
        finding_order=[f.title for f in ordered_findings],
    )


def _build_report(req: AnalyzeRequest, review_id: str, vendor_info: VendorDetection, config_hash: str, findings, risk_score, summary, pass_fail: bool) -> ReviewReport:
    template_name = req.template_name or ("Custom / Starter Template" if req.template_rules else "Default review")
    template_version = req.template_version or ("v1" if req.template_rules else "default")

    deviations = [
        TemplateComplianceItem(
            rule_name=f.title,
            severity=f.severity,
            status="fail",
            description=f.description,
        )
        for f in findings
        if getattr(f.category, "value", str(f.category)) == "compliance"
    ]

    total_template_rules = len(req.template_rules or [])
    failed_rules = len(deviations)
    passed_rules = max(total_template_rules - failed_rules, 0)

    ordered_change_script = _build_ordered_change_script(findings)

    return ReviewReport(
        review_id=review_id,
        format="json",
        header=ReportHeader(
            generated_at_utc=datetime.now(timezone.utc).isoformat(),
            engineer_identity=req.engineer_name or "Unknown engineer",
            config_hash=config_hash,
            template_version_used=f"{template_name} ({template_version})",
            platform_detected=f"{vendor_info.vendor.value}{' ' + vendor_info.os_version if vendor_info.os_version else ''}",
            hostname=vendor_info.hostname,
        ),
        body=ReportBody(
            executive_summary=ExecutiveSummary(
                pass_fail=pass_fail,
                pass_fail_label="PASS" if pass_fail else "FAIL",
                risk_score=risk_score.score,
                risk_grade=risk_score.grade,
                finding_counts={
                    "critical": summary.critical_count,
                    "warning": summary.warning_count,
                    "info": summary.info_count,
                    "total": summary.total_findings,
                },
                benchmark_label=risk_score.benchmark_label,
            ),
            findings_detail=findings,
            template_compliance=TemplateComplianceSummary(
                template_name=template_name,
                template_version=template_version,
                passed_rules=passed_rules,
                failed_rules=failed_rules,
                deviations=deviations,
            ),
            ordered_change_script=ordered_change_script,
            config_diff=None,
        ),
    )


def _verify_key(x_api_key: str = Header(None)):
    """Verify engine API key for internal calls."""
    if ENGINE_API_KEY and x_api_key != ENGINE_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid engine API key")


def _is_probably_text(raw: bytes) -> bool:
    return bool(raw) and b"\x00" not in raw[:4096]


def _extract_batch_zip(req: BatchReviewRequest) -> list[tuple[str, str]]:
    try:
        archive_bytes = base64.b64decode(req.zip_base64)
    except Exception as exc:  # pragma: no cover
        raise HTTPException(status_code=400, detail=f"Invalid ZIP payload: {exc}") from exc

    try:
        archive = zipfile.ZipFile(io.BytesIO(archive_bytes))
    except zipfile.BadZipFile as exc:
        raise HTTPException(status_code=400, detail="Uploaded file is not a valid ZIP archive.") from exc

    extracted: list[tuple[str, str]] = []
    for info in archive.infolist():
        if info.is_dir():
            continue

        suffixes = Path(info.filename).suffixes
        extension_match = any(suffix.lower() in ALLOWED_BATCH_EXTENSIONS for suffix in (suffixes[-2:] or suffixes))
        with archive.open(info) as handle:
            raw = handle.read()

        if not extension_match and not _is_probably_text(raw):
            continue

        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = raw.decode("latin-1")
            except UnicodeDecodeError:
                continue

        if text.strip():
            extracted.append((info.filename, text))

    if not extracted:
        raise HTTPException(status_code=400, detail="ZIP archive did not contain any readable config files.")
    if len(extracted) > 50:
        raise HTTPException(status_code=400, detail="Batch review supports up to 50 config files per ZIP upload.")
    return extracted


def _run_analysis(req: AnalyzeRequest) -> AnalyzeResponse:
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
    template_rules = req.template_rules
    if not template_rules and req.template_id:
        starter_template = get_starter_template(req.template_id)
        if starter_template:
            template_rules = starter_template.get("rules", [])
            if not req.template_name:
                req.template_name = starter_template.get("name")
            if not req.template_version:
                req.template_version = starter_template.get("version", "starter-v1")

    if template_rules:
        template_engine = TemplateEngine()
        findings.extend(template_engine.check(lines, template_rules, vendor_info.vendor))

    # 5. Normalize context snippets for better report readability
    findings = _attach_context(findings, lines)

    # 6. Compliance tagging
    tagger = ComplianceTagger()
    findings = tagger.tag_findings(findings)

    # 7. Generate remediation + rollback for findings that don't have them yet
    remediator = RemediationGenerator(vendor_info.vendor)
    findings = remediator.enrich(findings, lines)

    # 8. Snippet suppression — remove findings that require global context
    if snippet_info.is_snippet:
        original_count = len(findings)
        findings = [f for f in findings if f.category.value != "compliance" or "global" not in f.description.lower()]
        snippet_info.suppressed_checks = [
            f"Suppressed {original_count - len(findings)} global-context checks in snippet mode"
        ] if original_count > len(findings) else []

    # 9. Quick-pass filter
    if req.quick_pass:
        findings = [f for f in findings if f.severity.value == "critical"]

    # 10. Risk score
    risk_score = calculate_risk_score(findings, snippet_info.is_snippet)

    # 11. Summary
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

    pass_fail = critical_count == 0
    report = _build_report(req, review_id, vendor_info, config_hash, findings, risk_score, summary, pass_fail)

    return AnalyzeResponse(
        review_id=review_id,
        status=ReviewStatus.COMPLETE,
        vendor=vendor_info,
        snippet_info=snippet_info,
        findings=findings,
        risk_score=risk_score,
        pass_fail=pass_fail,
        summary=summary,
        config_hash=config_hash,
        report=report,
    )


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_config(req: AnalyzeRequest, _=Depends(_verify_key)):
    return _run_analysis(req)


@router.get("/templates/starter")
async def list_starter_templates(_=Depends(_verify_key)):
    """Return curated starter templates for day-one use."""
    return {"templates": load_starter_templates()}


@router.post("/report/render")
async def render_report(req: AnalyzeRequest, format: str = "html", _=Depends(_verify_key)):
    """Render a self-contained report artifact from the same underlying review data."""
    review = _run_analysis(req)
    if format == "pdf":
        pdf_bytes = render_report_pdf_bytes(review)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="config-review-{review.review_id}.pdf"'},
        )
    html = build_report_html(review)
    return HTMLResponse(content=html)


@router.post("/batch-review", response_model=BatchReviewResponse)
async def batch_review_configs(req: BatchReviewRequest, _=Depends(_verify_key)):
    """Review a ZIP of configs in one session and optionally run cross-config correlation."""
    extracted = _extract_batch_zip(req)
    reviews: list[BatchReviewItem] = []

    for filename, config_text in extracted:
        review = _run_analysis(
            AnalyzeRequest(
                config_text=config_text,
                vendor=req.vendor,
                template_id=req.template_id,
                template_name=req.template_name,
                template_version=req.template_version,
                engineer_name=req.engineer_name,
                template_rules=req.template_rules,
                quick_pass=req.quick_pass,
                snippet_mode=req.snippet_mode,
                context_hint=req.context_hint,
            )
        )
        reviews.append(BatchReviewItem(filename=filename, config_text=config_text, review=review))

    cross_config = None
    if 2 <= len(extracted) <= 10:
        findings, inferred_links = correlate_configs([
            {"config_text": config_text, "vendor": req.vendor, "hostname": None}
            for filename, config_text in extracted
        ])
        cross_config = CrossConfigResponse(
            findings=findings,
            inferred_links=inferred_links,
            summary={
                "critical": sum(1 for finding in findings if finding.severity.value == "critical"),
                "warning": sum(1 for finding in findings if finding.severity.value == "warning"),
                "info": sum(1 for finding in findings if finding.severity.value == "info"),
                "total": len(findings),
            },
        )

    total_findings = sum(item.review.summary.total_findings for item in reviews)
    critical_total = sum(item.review.summary.critical_count for item in reviews)
    warning_total = sum(item.review.summary.warning_count for item in reviews)
    info_total = sum(item.review.summary.info_count for item in reviews)
    pass_count = sum(1 for item in reviews if item.review.pass_fail)

    return BatchReviewResponse(
        review_count=len(reviews),
        filenames=[item.filename for item in reviews],
        reviews=reviews,
        cross_config=cross_config,
        summary={
            "configs_reviewed": len(reviews),
            "pass_count": pass_count,
            "fail_count": len(reviews) - pass_count,
            "critical": critical_total,
            "warning": warning_total,
            "info": info_total,
            "findings_total": total_findings,
        },
    )


@router.post("/compare", response_model=CompareResponse)
async def compare_configs(req: CompareRequest, _=Depends(_verify_key)):
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


@router.post("/correlate", response_model=CrossConfigResponse)
async def correlate_multi_config(req: CrossConfigRequest, _=Depends(_verify_key)):
    """Cross-device consistency review for 2-10 configs in a single session."""
    findings, inferred_links = correlate_configs([item.model_dump() for item in req.configs])
    summary = {
        "critical": sum(1 for finding in findings if finding.severity.value == "critical"),
        "warning": sum(1 for finding in findings if finding.severity.value == "warning"),
        "info": sum(1 for finding in findings if finding.severity.value == "info"),
        "total": len(findings),
    }
    return CrossConfigResponse(findings=findings, inferred_links=inferred_links, summary=summary)


@router.post("/query", response_model=NLQueryResponse)
async def query_config(req: NLQueryRequest, _=Depends(_verify_key)):
    """Natural language query against a config using Claude API."""
    detected = detect_vendor(req.config_text)
    vendor_info = detected if not req.vendor else VendorDetection(
        vendor=req.vendor,
        confidence=1.0,
        hostname=detected.hostname,
        os_version=detected.os_version,
    )
    return await answer_query(req.config_text, req.question, vendor_info)


@router.post("/query/multi", response_model=MultiConfigQueryResponse)
async def query_multi_config(req: MultiConfigQueryRequest, _=Depends(_verify_key)):
    """Natural language query across 2-10 configs in the current session."""
    normalized = []
    for item in req.configs:
        detected = detect_vendor(item.config_text)
        vendor_info = detected if not item.vendor else VendorDetection(
            vendor=item.vendor,
            confidence=1.0,
            hostname=item.hostname or detected.hostname,
            os_version=detected.os_version,
        )
        normalized.append(
            {
                "config_text": item.config_text,
                "hostname": item.hostname or vendor_info.hostname,
                "vendor_info": vendor_info,
            }
        )
    return await answer_multi_config_query(normalized, req.question)
