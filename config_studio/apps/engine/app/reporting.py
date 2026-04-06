"""Report rendering helpers for Config Studio."""

from __future__ import annotations

from html import escape
from typing import Optional

from app.api.schemas import ReviewReport, AnalyzeResponse


def _severity_color(severity: str) -> str:
    return {
        "critical": "#b91c1c",
        "warning": "#b45309",
        "info": "#1d4ed8",
    }.get(severity, "#334155")


def build_report_html(review: AnalyzeResponse) -> str:
    report = review.report
    summary = report.body.executive_summary
    findings_html = "".join(
        f"""
        <div class=\"finding\" style=\"border-left: 6px solid {_severity_color(f.severity.value)};\">
          <h3>{escape(f.title)}</h3>
          <p><strong>Severity:</strong> {escape(f.severity.value.title())} &nbsp; <strong>Category:</strong> {escape(f.category.value.replace('_', ' ').title())}</p>
          <p><strong>Lines:</strong> {f.line_start}-{f.line_end}</p>
          <p>{escape(f.description)}</p>
          <p><strong>Remediation</strong></p>
          <pre>{escape(f.remediation)}</pre>
          <p><strong>Rollback</strong></p>
          <pre>{escape(f.rollback)}</pre>
          {f'<p><strong>Reference:</strong> {escape(f.reference_url)}</p>' if f.reference_url else ''}
          {f'<p><strong>Compliance tags:</strong> {escape(', '.join(f.compliance_tags))}</p>' if f.compliance_tags else ''}
          {f'<p><strong>Config context</strong></p><pre>{escape(f.config_context)}</pre>' if f.config_context else ''}
        </div>
        """
        for f in report.body.findings_detail
    ) or "<p>No findings in this review.</p>"

    deviations_html = "".join(
        f"<li><strong>{escape(item.rule_name)}</strong> — {escape(item.severity.value.title())}: {escape(item.description)}</li>"
        for item in report.body.template_compliance.deviations
    ) or "<li>No template deviations recorded.</li>"

    ordered_script = report.body.ordered_change_script
    ordered_script_html = ""
    if ordered_script and ordered_script.generated:
        ordered_script_html = f"""
  <div class=\"card\" style=\"margin-bottom: 18px;\">
    <h2>Ordered change script</h2>
    <p>{escape(ordered_script.rationale or '')}</p>
    <p><strong>Finding order:</strong> {escape(' → '.join(ordered_script.finding_order))}</p>
    <p><strong>Apply script</strong></p>
    <pre>{escape(ordered_script.apply_script)}</pre>
    <p><strong>Rollback script</strong></p>
    <pre>{escape(ordered_script.rollback_script)}</pre>
  </div>
"""

    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <title>Config Studio Report {escape(report.review_id)}</title>
  <style>
    body {{ font-family: Arial, Helvetica, sans-serif; margin: 32px; color: #0f172a; }}
    h1, h2, h3 {{ margin-bottom: 8px; }}
    .muted {{ color: #475569; }}
    .grid {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin: 18px 0; }}
    .card {{ border: 1px solid #cbd5e1; border-radius: 10px; padding: 14px; background: #f8fafc; }}
    .finding {{ border: 1px solid #cbd5e1; border-radius: 10px; padding: 14px; margin-bottom: 14px; background: white; }}
    pre {{ white-space: pre-wrap; background: #f8fafc; border: 1px solid #e2e8f0; padding: 10px; border-radius: 8px; }}
    ul {{ padding-left: 20px; }}
    .pill {{ display: inline-block; padding: 4px 8px; border-radius: 999px; background: {'#dcfce7' if summary.pass_fail else '#fee2e2'}; color: {'#166534' if summary.pass_fail else '#991b1b'}; font-weight: bold; }}
  </style>
</head>
<body>
  <h1>Optimesh Config Studio Pre-Flight Report</h1>
  <p class=\"muted\">Self-contained report artifact for offline review and audit attachment.</p>

  <div class=\"grid\">
    <div class=\"card\">
      <h2>Report header</h2>
      <p><strong>Generated (UTC):</strong> {escape(report.header.generated_at_utc)}</p>
      <p><strong>Engineer:</strong> {escape(report.header.engineer_identity)}</p>
      <p><strong>Hostname:</strong> {escape(report.header.hostname or 'Unknown')}</p>
      <p><strong>Platform detected:</strong> {escape(report.header.platform_detected)}</p>
      <p><strong>Template version:</strong> {escape(report.header.template_version_used)}</p>
      <p><strong>Config hash:</strong> {escape(report.header.config_hash)}</p>
    </div>
    <div class=\"card\">
      <h2>Executive summary</h2>
      <p><span class=\"pill\">{escape(summary.pass_fail_label)}</span></p>
      <p><strong>Risk score:</strong> {summary.risk_score} ({escape(summary.risk_grade)})</p>
      <p><strong>Benchmark:</strong> {escape(summary.benchmark_label)}</p>
      <p><strong>Finding counts:</strong> Critical {summary.finding_counts.get('critical', 0)} · Warning {summary.finding_counts.get('warning', 0)} · Info {summary.finding_counts.get('info', 0)} · Total {summary.finding_counts.get('total', 0)}</p>
    </div>
  </div>

  <div class=\"card\" style=\"margin-bottom: 18px;\">
    <h2>Golden template compliance</h2>
    <p><strong>Template:</strong> {escape(report.body.template_compliance.template_name)} ({escape(report.body.template_compliance.template_version)})</p>
    <p><strong>Passed rules:</strong> {report.body.template_compliance.passed_rules} · <strong>Failed rules:</strong> {report.body.template_compliance.failed_rules}</p>
    <ul>{deviations_html}</ul>
  </div>

  {ordered_script_html}

  <h2>Findings detail</h2>
  {findings_html}
</body>
</html>
"""


def render_report_pdf_bytes(review: AnalyzeResponse) -> bytes:
    """Return a lightweight PDF-like artifact for download.

    This keeps the underlying report data identical to the JSON report while
    providing a human-readable `.pdf` export path for MVP demos. The payload is
    a minimal PDF wrapper around the rendered HTML/text content so the UI and
    downstream tools can download a document artifact immediately.
    """
    html = build_report_html(review)
    text = html.replace("<br>", "\n")
    minimal_pdf = (
        "%PDF-1.4\n"
        "1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n"
        "2 0 obj<< /Type /Pages /Count 1 /Kids [3 0 R] >>endobj\n"
        "3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources<< /Font<< /F1 5 0 R >> >> >>endobj\n"
        f"4 0 obj<< /Length {len(text) + 64} >>stream\nBT /F1 10 Tf 40 760 Td ({text[:4000].replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')}) Tj ET\nendstream endobj\n"
        "5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n"
        "xref\n0 6\n0000000000 65535 f \n"
        "trailer<< /Root 1 0 R /Size 6 >>\nstartxref\n0\n%%EOF"
    )
    return minimal_pdf.encode("utf-8", errors="ignore")
