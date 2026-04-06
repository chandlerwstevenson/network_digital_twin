"""Golden Template Engine — matches configs against org-defined rules."""

from __future__ import annotations

import re
import uuid

from app.api.schemas import (
    Finding, Severity, FindingCategory, Vendor,
    TemplateRule, RuleType,
)


class TemplateEngine:
    """Evaluate config against a set of template rules."""

    def check(
        self,
        lines: list[str],
        rules: list[TemplateRule],
        vendor: Vendor,
    ) -> list[Finding]:
        findings: list[Finding] = []
        full_text = "\n".join(lines)

        for rule in rules:
            rule_findings = self._evaluate_rule(rule, lines, full_text)
            findings.extend(rule_findings)

        return findings

    def _evaluate_rule(
        self,
        rule: TemplateRule,
        lines: list[str],
        full_text: str,
    ) -> list[Finding]:
        if rule.rule_type == RuleType.REQUIRED_COMMAND:
            return self._check_required(rule, lines, full_text)
        elif rule.rule_type == RuleType.BANNED_COMMAND:
            return self._check_banned(rule, lines, full_text)
        elif rule.rule_type == RuleType.REQUIRED_VALUE:
            return self._check_required_value(rule, lines, full_text)
        elif rule.rule_type == RuleType.NAMING_CONVENTION:
            return self._check_naming(rule, lines)
        elif rule.rule_type == RuleType.STRUCTURAL:
            return self._check_structural(rule, lines, full_text)
        return []

    def _check_required(
        self, rule: TemplateRule, lines: list[str], full_text: str,
    ) -> list[Finding]:
        """Check that a required command exists in the config."""
        pattern = rule.pattern or ""
        if not pattern:
            return []

        # If section scope is specified, only search within that section
        if rule.section:
            search_text = self._extract_section(lines, rule.section)
        else:
            search_text = full_text

        if not re.search(pattern, search_text, re.MULTILINE | re.IGNORECASE):
            return [Finding(
                id=str(uuid.uuid4()),
                line_start=1,
                line_end=1,
                severity=rule.severity,
                category=FindingCategory.COMPLIANCE,
                title=f"Missing required: {rule.name}",
                description=f"Template rule '{rule.name}': {rule.description}. "
                            f"Expected pattern '{pattern}' was not found in the config.",
                remediation=f"! Add the required configuration:\n! Pattern: {pattern}",
                rollback=f"! Remove the added configuration",
                compliance_tags=["golden-template"],
            )]
        return []

    def _check_banned(
        self, rule: TemplateRule, lines: list[str], full_text: str,
    ) -> list[Finding]:
        """Check that a banned command does not exist in the config."""
        pattern = rule.pattern or ""
        if not pattern:
            return []

        findings = []
        for i, line in enumerate(lines):
            stripped = line.strip()
            if re.search(pattern, stripped, re.IGNORECASE):
                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    line_start=i + 1,
                    line_end=i + 1,
                    severity=rule.severity,
                    category=FindingCategory.COMPLIANCE,
                    title=f"Banned command: {rule.name}",
                    description=f"Template rule '{rule.name}': {rule.description}. "
                                f"Banned pattern '{pattern}' found at line {i + 1}.",
                    remediation=f"configure terminal\nno {stripped}\nend",
                    rollback=f"configure terminal\n{stripped}\nend",
                    compliance_tags=["golden-template"],
                    config_context=stripped,
                ))
        return findings

    def _check_required_value(
        self, rule: TemplateRule, lines: list[str], full_text: str,
    ) -> list[Finding]:
        """Check that a specific value matches expectations."""
        pattern = rule.pattern or ""
        expected = rule.expected_value or ""
        if not pattern:
            return []

        for i, line in enumerate(lines):
            m = re.search(pattern, line.strip(), re.IGNORECASE)
            if m:
                actual_value = m.group(1) if m.lastindex else m.group(0)
                if expected and actual_value.lower() != expected.lower():
                    return [Finding(
                        id=str(uuid.uuid4()),
                        line_start=i + 1,
                        line_end=i + 1,
                        severity=rule.severity,
                        category=FindingCategory.COMPLIANCE,
                        title=f"Value mismatch: {rule.name}",
                        description=f"Template rule '{rule.name}': Expected '{expected}' but found '{actual_value}'. "
                                    f"{rule.description}",
                        remediation=f"! Change value to: {expected}",
                        rollback=f"! Restore original value: {actual_value}",
                        compliance_tags=["golden-template"],
                        config_context=line.strip(),
                    )]
        return []

    def _check_naming(self, rule: TemplateRule, lines: list[str]) -> list[Finding]:
        """Check naming conventions (e.g., interface descriptions must match pattern)."""
        pattern = rule.pattern or ""
        section = rule.section or "interface"
        if not pattern:
            return []

        findings = []
        in_section = False
        section_start = 0

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.lower().startswith(section.lower()):
                in_section = True
                section_start = i + 1
            elif in_section and not line.startswith(" ") and stripped:
                in_section = False
            elif in_section and stripped.lower().startswith("description"):
                desc_value = stripped.split(None, 1)[1] if len(stripped.split(None, 1)) > 1 else ""
                if not re.match(pattern, desc_value, re.IGNORECASE):
                    findings.append(Finding(
                        id=str(uuid.uuid4()),
                        line_start=i + 1,
                        line_end=i + 1,
                        severity=rule.severity,
                        category=FindingCategory.COMPLIANCE,
                        title=f"Naming violation: {rule.name}",
                        description=f"Description '{desc_value}' does not match required pattern '{pattern}'. "
                                    f"{rule.description}",
                        remediation=f"! Update description to match pattern: {pattern}",
                        rollback=f"! Restore original description: {desc_value}",
                        compliance_tags=["golden-template"],
                        config_context=stripped,
                    ))

        return findings

    def _check_structural(
        self, rule: TemplateRule, lines: list[str], full_text: str,
    ) -> list[Finding]:
        """Structural rules (e.g., 'every trunk interface must have storm-control')."""
        section = rule.section or ""
        condition = rule.condition or ""
        pattern = rule.pattern or ""

        if not section or not pattern:
            return []

        findings = []
        in_section = False
        section_name = ""
        section_start = 0
        section_lines: list[str] = []

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.lower().startswith(section.lower()):
                if in_section and section_lines:
                    finding = self._check_structural_section(
                        rule, section_name, section_start, section_lines, condition, pattern
                    )
                    if finding:
                        findings.append(finding)
                in_section = True
                section_name = stripped
                section_start = i + 1
                section_lines = []
            elif in_section and (line.startswith(" ") or line.startswith("\t")):
                section_lines.append(stripped)
            elif in_section and stripped and not stripped.startswith("!"):
                finding = self._check_structural_section(
                    rule, section_name, section_start, section_lines, condition, pattern
                )
                if finding:
                    findings.append(finding)
                in_section = False

        # Last section
        if in_section and section_lines:
            finding = self._check_structural_section(
                rule, section_name, section_start, section_lines, condition, pattern
            )
            if finding:
                findings.append(finding)

        return findings

    def _check_structural_section(
        self,
        rule: TemplateRule,
        section_name: str,
        section_start: int,
        section_lines: list[str],
        condition: str,
        pattern: str,
    ) -> Finding | None:
        """Check if a structural rule is satisfied within a section."""
        section_text = "\n".join(section_lines)

        # Check condition (if specified, section must match condition to be checked)
        if condition:
            if not re.search(condition, section_text, re.IGNORECASE):
                return None

        # Check required pattern
        if not re.search(pattern, section_text, re.IGNORECASE):
            return Finding(
                id=str(uuid.uuid4()),
                line_start=section_start,
                line_end=section_start + len(section_lines),
                severity=rule.severity,
                category=FindingCategory.COMPLIANCE,
                title=f"Structural violation: {rule.name}",
                description=f"{section_name}: {rule.description}. Expected pattern '{pattern}' not found.",
                remediation=f"! Add required configuration under {section_name}",
                rollback=f"! Remove added configuration",
                compliance_tags=["golden-template"],
            )
        return None

    @staticmethod
    def _extract_section(lines: list[str], section_prefix: str) -> str:
        """Extract all lines belonging to sections matching the prefix."""
        result = []
        in_section = False
        for line in lines:
            stripped = line.strip()
            if stripped.lower().startswith(section_prefix.lower()):
                in_section = True
                result.append(stripped)
            elif in_section and (line.startswith(" ") or line.startswith("\t")):
                result.append(stripped)
            elif in_section:
                in_section = False
        return "\n".join(result)
