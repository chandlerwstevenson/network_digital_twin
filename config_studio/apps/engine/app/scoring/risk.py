"""Risk score calculation (0-100, where 100 = highest risk).

The score is derived from finding severity and categories with
industry benchmarking context for first-review display (REQ-5.2).
"""

from __future__ import annotations

from app.api.schemas import Finding, RiskScore


# Weights per severity
_SEVERITY_WEIGHTS = {
    "critical": 25,
    "warning": 8,
    "info": 2,
}

# Category multipliers (security issues are weighted higher)
_CATEGORY_MULTIPLIERS = {
    "security": 1.5,
    "syntax": 1.0,
    "compliance": 1.2,
    "best_practice": 0.8,
}

# Grade thresholds
_GRADES = [
    (0, 15, "A"),
    (16, 35, "B"),
    (36, 55, "C"),
    (56, 75, "D"),
    (76, 100, "F"),
]

# Industry benchmark labels
_BENCHMARKS = {
    "A": "excellent — top 10% of enterprise networks",
    "B": "good — above average for mid-market regulated environments",
    "C": "typical for mid-market pharma networks",
    "D": "below average — significant risk exposure",
    "F": "critical — immediate remediation recommended",
}


def calculate_risk_score(findings: list[Finding], is_snippet: bool = False) -> RiskScore:
    """Calculate a 0-100 risk score from findings.

    Lower is better. Score is capped at 100.
    For snippet mode, findings are weighted lower since they represent
    a partial config and global checks are suppressed.
    """
    if not findings:
        return RiskScore(
            score=0,
            grade="A",
            benchmark_label=_BENCHMARKS["A"],
            breakdown={},
        )

    raw_score = 0.0
    breakdown: dict[str, int] = {}

    for finding in findings:
        severity = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)
        category = finding.category.value if hasattr(finding.category, "value") else str(finding.category)

        weight = _SEVERITY_WEIGHTS.get(severity, 5)
        multiplier = _CATEGORY_MULTIPLIERS.get(category, 1.0)
        contribution = weight * multiplier

        raw_score += contribution
        breakdown[category] = breakdown.get(category, 0) + int(contribution)

    # Snippet mode: reduce score since it's a partial view
    if is_snippet:
        raw_score *= 0.5

    # Normalize: cap at 100, apply logarithmic scaling for large finding counts
    import math
    if raw_score > 50:
        score = min(100, int(50 + 50 * math.log(raw_score / 50 + 1) / math.log(3)))
    else:
        score = min(100, int(raw_score))

    # Determine grade
    grade = "C"
    for low, high, g in _GRADES:
        if low <= score <= high:
            grade = g
            break

    return RiskScore(
        score=score,
        grade=grade,
        benchmark_label=_BENCHMARKS.get(grade, _BENCHMARKS["C"]),
        breakdown=breakdown,
    )
