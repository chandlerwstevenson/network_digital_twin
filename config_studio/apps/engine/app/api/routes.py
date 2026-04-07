"""API routes for the analysis engine."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import mimetypes
import urllib.error
import urllib.request
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
    PipelineReviewRequest,
    PipelineReviewResponse,
    ReviewExportRequest,
    ReviewExportResponse,
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
SEVERITY_RANK = {"info": 1, "warning": 2, "critical": 3}


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


def _build_auth_headers(auth) -> dict[str, str]:
    if auth.auth_type.value == "basic":
        if not auth.username or auth.password is None:
            raise HTTPException(status_code=400, detail="Basic auth requires username and password.")
        token = base64.b64encode(f"{auth.username}:{auth.password}".encode("utf-8")).decode("ascii")
        return {"Authorization": f"Basic {token}"}

    if not auth.token:
        raise HTTPException(status_code=400, detail="Bearer auth requires token.")
    return {"Authorization": f"Bearer {auth.token}"}


def _http_request_json(url: str, method: str, payload: dict | None, headers: dict[str, str]) -> dict[str, str | bool | int | None]:
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request_headers = {"Content-Type": "application/json", **headers}
    request = urllib.request.Request(url, data=body, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return {
                "attempted": True,
                "delivered": 200 <= response.status < 300,
                "status_code": response.status,
                "detail": response.read().decode("utf-8", errors="replace")[:500] or f"{method} {url} succeeded.",
            }
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        return {
            "attempted": True,
            "delivered": False,
            "status_code": exc.code,
            "detail": detail or f"{method} {url} returned HTTP {exc.code}.",
        }
    except Exception as exc:  # pragma: no cover
        return {
            "attempted": True,
            "delivered": False,
            "status_code": None,
            "detail": str(exc),
        }


def _encode_multipart(parts: list[dict[str, str | bytes]]) -> tuple[bytes, str]:
    boundary = f"----ConfigStudioBoundary{uuid.uuid4().hex}"
    body = bytearray()
    for part in parts:
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        disposition = f'Content-Disposition: form-data; name="{part["name"]}"'
        filename = part.get("filename")
        if filename:
            disposition += f'; filename="{filename}"'
        body.extend(f"{disposition}\r\n".encode("utf-8"))
        content_type = part.get("content_type")
        if content_type:
            body.extend(f"Content-Type: {content_type}\r\n".encode("utf-8"))
        body.extend(b"\r\n")
        data = part.get("data", "")
        body.extend(data if isinstance(data, bytes) else str(data).encode("utf-8"))
        body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode("utf-8"))
    return bytes(body), boundary


def _http_request_multipart(url: str, method: str, parts: list[dict[str, str | bytes]], headers: dict[str, str]) -> dict[str, str | bool | int | None]:
    body, boundary = _encode_multipart(parts)
    request_headers = {"Content-Type": f"multipart/form-data; boundary={boundary}", **headers}
    request = urllib.request.Request(url, data=body, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return {
                "attempted": True,
                "delivered": 200 <= response.status < 300,
                "status_code": response.status,
                "detail": response.read().decode("utf-8", errors="replace")[:500] or f"{method} {url} succeeded.",
            }
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        return {
            "attempted": True,
            "delivered": False,
            "status_code": exc.code,
            "detail": detail or f"{method} {url} returned HTTP {exc.code}.",
        }
    except Exception as exc:  # pragma: no cover
        return {
            "attempted": True,
            "delivered": False,
            "status_code": None,
            "detail": str(exc),
        }


def _send_review_webhook(webhook_url: str, payload: dict, headers: dict[str, str] | None = None) -> dict[str, str | bool | int | None]:
    return _http_request_json(webhook_url, "POST", payload, headers or {})


def _render_export_artifacts(review, attachment_prefix: str, include_pdf: bool, include_json: bool, include_html: bool) -> list[dict[str, str | bytes | int]]:
    artifacts: list[dict[str, str | bytes | int]] = []
    safe_prefix = attachment_prefix.strip() or "config-studio-review"
    if include_json:
        artifacts.append(
            {
                "filename": f"{safe_prefix}-{review.review_id}.json",
                "content_type": "application/json",
                "data": json.dumps(review.report.model_dump(), indent=2).encode("utf-8"),
            }
        )
    if include_html:
        artifacts.append(
            {
                "filename": f"{safe_prefix}-{review.review_id}.html",
                "content_type": "text/html",
                "data": build_report_html(review).encode("utf-8"),
            }
        )
    if include_pdf:
        artifacts.append(
            {
                "filename": f"{safe_prefix}-{review.review_id}.pdf",
                "content_type": "application/pdf",
                "data": render_report_pdf_bytes(review),
            }
        )
    return artifacts


def _build_export_summary_text(review, export_comment: str | None = None) -> str:
    summary = review.report.body.executive_summary
    lines = [
        "Config Studio review export",
        f"Review ID: {review.review_id}",
        f"Hostname: {review.report.header.hostname or 'unknown'}",
        f"Platform: {review.report.header.platform_detected}",
        f"Status: {summary.pass_fail_label}",
        f"Risk score: {summary.risk_score} ({summary.risk_grade})",
        f"Findings: critical {summary.finding_counts.get('critical', 0)}, warning {summary.finding_counts.get('warning', 0)}, info {summary.finding_counts.get('info', 0)}, total {summary.finding_counts.get('total', 0)}",
        f"Config hash: {review.config_hash}",
    ]
    if export_comment:
        lines.extend(["", export_comment.strip()])
    return "\n".join(lines)


def _export_review_to_servicenow(req: ReviewExportRequest, review) -> tuple[list[dict[str, str | int]], dict[str, str | bool | int | None], dict[str, str]]:
    if not req.service_now:
        raise HTTPException(status_code=400, detail="service_now options are required for ServiceNow export.")

    headers = {"Accept": "application/json", **_build_auth_headers(req.auth)}
    instance = req.service_now.instance_url.rstrip("/")
    artifacts = _render_export_artifacts(review, req.attachment_prefix, req.include_pdf, req.include_json, req.include_html)
    attachment_results: list[dict[str, str | int]] = []
    for artifact in artifacts:
        url = (
            f"{instance}/api/now/attachment/file?table_name={req.service_now.table_name}"
            f"&table_sys_id={req.service_now.record_sys_id}&file_name={artifact['filename']}"
        )
        result = _http_request_multipart(
            url,
            "POST",
            [{
                "name": "file",
                "filename": str(artifact["filename"]),
                "content_type": str(artifact["content_type"]),
                "data": artifact["data"],
            }],
            headers,
        )
        attachment_results.append(
            {
                "filename": str(artifact["filename"]),
                "content_type": str(artifact["content_type"]),
                "bytes": len(artifact["data"]),
                "status_code": int(result.get("status_code") or 0),
            }
        )

    comment_result = {"attempted": False, "delivered": False, "status_code": None, "detail": None}
    if req.service_now.update_work_notes or req.service_now.update_short_description:
        payload: dict[str, str] = {}
        if req.service_now.update_work_notes:
            payload["work_notes"] = _build_export_summary_text(review, req.export_comment)
        if req.service_now.update_short_description:
            payload["short_description"] = f"Config Studio {review.report.body.executive_summary.pass_fail_label}: {review.report.header.hostname or 'Unknown device'}"
        comment_result = _http_request_json(
            f"{instance}/api/now/table/{req.service_now.table_name}/{req.service_now.record_sys_id}",
            "PATCH",
            payload,
            headers,
        )

    return attachment_results, comment_result, {
        "platform": "ServiceNow",
        "instance_url": instance,
        "table_name": req.service_now.table_name,
        "record_sys_id": req.service_now.record_sys_id,
    }


def _export_review_to_jira(req: ReviewExportRequest, review) -> tuple[list[dict[str, str | int]], dict[str, str | bool | int | None], dict[str, str]]:
    if not req.jira:
        raise HTTPException(status_code=400, detail="jira options are required for Jira export.")

    base_url = req.jira.base_url.rstrip("/")
    auth_headers = {"Accept": "application/json", **_build_auth_headers(req.auth)}
    artifacts = _render_export_artifacts(review, req.attachment_prefix, req.include_pdf, req.include_json, req.include_html)
    attachment_results: list[dict[str, str | int]] = []
    for artifact in artifacts:
        result = _http_request_multipart(
            f"{base_url}/rest/api/3/issue/{req.jira.issue_key}/attachments",
            "POST",
            [{
                "name": "file",
                "filename": str(artifact["filename"]),
                "content_type": str(artifact["content_type"]),
                "data": artifact["data"],
            }],
            {**auth_headers, "X-Atlassian-Token": "no-check"},
        )
        attachment_results.append(
            {
                "filename": str(artifact["filename"]),
                "content_type": str(artifact["content_type"]),
                "bytes": len(artifact["data"]),
                "status_code": int(result.get("status_code") or 0),
            }
        )

    comment_result = {"attempted": False, "delivered": False, "status_code": None, "detail": None}
    if req.jira.add_comment:
        comment_result = _http_request_json(
            f"{base_url}/rest/api/3/issue/{req.jira.issue_key}/comment",
            "POST",
            {
                "body": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [{"type": "text", "text": _build_export_summary_text(review, req.export_comment)}],
                        }
                    ],
                }
            },
            auth_headers,
        )

    return attachment_results, comment_result, {
        "platform": "Jira Cloud",
        "base_url": base_url,
        "issue_key": req.jira.issue_key,
    }


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


@router.post("/pipeline/review", response_model=PipelineReviewResponse)
async def pipeline_review(req: PipelineReviewRequest, _=Depends(_verify_key)):
    """CI/CD-friendly review endpoint for pre-merge and pre-deploy gates."""
    review = _run_analysis(
        AnalyzeRequest(
            config_text=req.config_text,
            vendor=req.vendor,
            os_version=req.os_version,
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

    threshold = req.fail_on_severity.value
    blocking_findings = [
        finding for finding in review.findings
        if SEVERITY_RANK.get(finding.severity.value, 0) >= SEVERITY_RANK.get(threshold, 0)
    ]
    blocking_count = len(blocking_findings)
    should_block = blocking_count > 0
    if req.max_blocking_findings is not None:
        should_block = blocking_count >= req.max_blocking_findings

    response = PipelineReviewResponse(
        gate_status="block" if should_block else "pass",
        should_block=should_block,
        fail_on_severity=req.fail_on_severity,
        blocking_findings_count=blocking_count,
        max_blocking_findings=req.max_blocking_findings,
        blocking_findings=blocking_findings,
        summary={
            "review_id": review.review_id,
            "pass_fail": review.pass_fail,
            "config_hash": review.config_hash,
            "platform_detected": review.report.header.platform_detected,
            "hostname": review.report.header.hostname or "unknown",
            "total_findings": review.summary.total_findings,
            "critical": review.summary.critical_count,
            "warning": review.summary.warning_count,
            "info": review.summary.info_count,
        },
        review=review if req.include_review else None,
        webhook={"attempted": False, "delivered": False, "status_code": None, "detail": None},
    )

    if req.webhook_url:
        response.webhook = _send_review_webhook(
            req.webhook_url,
            {
                "event": "config_review.completed",
                "gate_status": response.gate_status,
                "should_block": response.should_block,
                "fail_on_severity": response.fail_on_severity.value,
                "blocking_findings_count": response.blocking_findings_count,
                "summary": response.summary,
                "review": response.review.model_dump() if response.review else None,
            },
            req.webhook_headers,
        )

    return response


@router.post("/export/review", response_model=ReviewExportResponse)
async def export_review(req: ReviewExportRequest, _=Depends(_verify_key)):
    """Render a review and attach its artifacts to ServiceNow or Jira Cloud."""
    review = _run_analysis(
        AnalyzeRequest(
            config_text=req.config_text,
            vendor=req.vendor,
            os_version=req.os_version,
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

    if req.target.value == "servicenow":
        attachments, comment_result, destination = _export_review_to_servicenow(req, review)
    else:
        attachments, comment_result, destination = _export_review_to_jira(req, review)

    return ReviewExportResponse(
        target=req.target,
        review_id=review.review_id,
        destination=destination,
        attachments=attachments,
        comment=comment_result,
        summary={
            "hostname": review.report.header.hostname or "unknown",
            "platform_detected": review.report.header.platform_detected,
            "pass_fail": review.report.body.executive_summary.pass_fail_label,
            "risk_score": review.report.body.executive_summary.risk_score,
            "attachments_attempted": len(attachments),
            "comment_attempted": bool(comment_result.get("attempted")),
        },
        review=review,
    )


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
