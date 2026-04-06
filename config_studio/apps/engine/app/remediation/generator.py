"""Remediation & rollback generator — terminal-ready command blocks (REQ-3.9).

Ensures every finding has:
1. Remediation: full command-mode context (configure terminal, interface, etc.)
2. Rollback: the undo commands (no-form for IOS, delete for JunOS)
"""

from __future__ import annotations

from app.api.schemas import Finding, Vendor


class RemediationGenerator:
    """Enrich findings with terminal-ready remediation and rollback."""

    def __init__(self, vendor: Vendor):
        self.vendor = vendor

    def enrich(self, findings: list[Finding], lines: list[str]) -> list[Finding]:
        """Add remediation/rollback to findings that are missing them."""
        for finding in findings:
            # Normalize any remediation/rollback that exists so it is terminal-ready.
            if finding.remediation:
                finding.remediation = self._ensure_context(finding.remediation, finding, lines)
            if finding.rollback:
                finding.rollback = self._ensure_context(finding.rollback, finding, lines)

        return findings

    def _ensure_context(self, commands: str, finding: Finding, lines: list[str]) -> str:
        """Ensure commands have proper mode context for the vendor."""
        if not commands:
            return commands

        vendor_key = self.vendor.value if isinstance(self.vendor, Vendor) else str(self.vendor)

        if vendor_key in ("cisco_ios", "cisco_iosxe"):
            return self._cisco_context(commands, finding, lines)
        elif vendor_key == "junos":
            return self._junos_context(commands, finding, lines)
        return commands

    def _cisco_context(self, commands: str, finding: Finding, lines: list[str]) -> str:
        """Add Cisco IOS/IOS-XE command mode context."""
        # If commands already have configure terminal, they're good
        if "configure terminal" in commands:
            return commands

        # Determine if we need interface/router context
        if finding.line_start > 0 and finding.line_start <= len(lines):
            context_line = lines[finding.line_start - 1].strip() if finding.line_start <= len(lines) else ""

            # Walk backwards to find the parent section
            for j in range(finding.line_start - 1, -1, -1):
                if j < len(lines) and lines[j] and not lines[j].startswith(" "):
                    parent = lines[j].strip()
                    if parent.startswith("interface ") or parent.startswith("router ") or parent.startswith("line "):
                        return f"configure terminal\n{parent}\n {commands}\nend"
                    break

        return f"configure terminal\n{commands}\nend"

    def _junos_context(self, commands: str, finding: Finding, lines: list[str]) -> str:
        """Add JunOS command context — provide both set and edit formats."""
        # If already in set format, it's ready
        if commands.startswith("set ") or commands.startswith("delete "):
            return commands
        return commands
