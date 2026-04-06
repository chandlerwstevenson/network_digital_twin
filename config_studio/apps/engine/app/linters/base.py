"""Base linter interface."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from app.api.schemas import Finding, Severity, FindingCategory


class BaseLinter(ABC):
    """Abstract base for all linters."""

    @abstractmethod
    def lint(self, lines: list[str]) -> list[Finding]:
        """Run lint checks and return findings."""
        ...

    @staticmethod
    def _make_finding(
        line_start: int,
        line_end: int,
        severity: Severity,
        category: FindingCategory,
        title: str,
        description: str,
        remediation: str = "",
        rollback: str = "",
        reference_url: str | None = None,
        compliance_tags: list[str] | None = None,
        config_context: str | None = None,
    ) -> Finding:
        return Finding(
            id=str(uuid.uuid4()),
            line_start=line_start,
            line_end=line_end,
            severity=severity,
            category=category,
            title=title,
            description=description,
            remediation=remediation,
            rollback=rollback,
            reference_url=reference_url,
            compliance_tags=compliance_tags or [],
            config_context=config_context,
        )
