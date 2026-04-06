"""Syntax linter — version-aware deprecated/removed command detection."""

from __future__ import annotations

import re
from app.api.schemas import Finding, Severity, FindingCategory, Vendor
from app.linters.base import BaseLinter


# Deprecated/removed commands by vendor and version
_DEPRECATED_COMMANDS: dict[str, list[dict]] = {
    "cisco_ios": [
        {
            "pattern": r"^ip classless",
            "min_version": "15.0",
            "title": "Deprecated command: ip classless",
            "description": "'ip classless' is the default behavior since IOS 12.0 and is deprecated in IOS 15.x+. Remove it to avoid confusion.",
            "remediation": "configure terminal\nno ip classless\nend",
            "rollback": "configure terminal\nip classless\nend",
            "ref": "https://www.cisco.com/c/en/us/td/docs/ios/fundamentals/command/reference/cf_book.html",
        },
        {
            "pattern": r"^ip subnet-zero",
            "min_version": "15.0",
            "title": "Deprecated command: ip subnet-zero",
            "description": "'ip subnet-zero' is enabled by default since IOS 12.0. This command is unnecessary.",
            "remediation": "configure terminal\nno ip subnet-zero\nend",
            "rollback": "configure terminal\nip subnet-zero\nend",
        },
        {
            "pattern": r"^crypto map\s+",
            "min_version": "16.0",
            "title": "Legacy crypto map detected",
            "description": "Crypto maps are deprecated in IOS-XE 16.x+ in favor of Tunnel Protection with IPSec profiles. Crypto maps still work but are not recommended for new deployments.",
            "remediation": "! Migrate to tunnel interface with IPSec profile\n! See Cisco IOS-XE migration guide for crypto map to tunnel protection",
            "rollback": "! Re-apply existing crypto map configuration",
            "ref": "https://www.cisco.com/c/en/us/support/docs/security-vpn/ipsec-negotiation-ike-protocols/215470-understand-ipsec-tunnel-negotiations.html",
        },
    ],
    "cisco_iosxe": [
        {
            "pattern": r"^crypto map\s+",
            "title": "Legacy crypto map detected",
            "description": "Crypto maps are deprecated in IOS-XE in favor of Tunnel Protection with IPSec profiles.",
            "remediation": "! Migrate to tunnel interface with IPSec profile",
            "rollback": "! Re-apply existing crypto map configuration",
        },
        {
            "pattern": r"^mls qos",
            "title": "MLS QoS not supported on IOS-XE",
            "description": "'mls qos' is an IOS-only command and does not exist on IOS-XE platforms. QoS is always enabled on IOS-XE. Use MQC (Modular QoS CLI) instead.",
            "remediation": "configure terminal\nno mls qos\nend\n! Use class-map / policy-map for QoS on IOS-XE",
            "rollback": "! N/A — command is not valid on this platform",
        },
    ],
    "junos": [
        {
            "pattern": r"set\s+system\s+root-authentication\s+plain-text-password",
            "title": "Plaintext root password in config",
            "description": "Setting root password in plaintext exposes the credential. Use encrypted-password instead.",
            "remediation": "set system root-authentication encrypted-password \"$6$...\"",
            "rollback": "delete system root-authentication encrypted-password",
        },
    ],
}

# Commands that should never appear in any modern config
_UNIVERSAL_BAD_COMMANDS = [
    {
        "pattern": r"^service\s+pad\b",
        "title": "X.25 PAD service enabled",
        "description": "X.25 PAD service is a legacy protocol that should be disabled. It presents an unnecessary attack surface.",
        "remediation": "configure terminal\nno service pad\nend",
        "rollback": "configure terminal\nservice pad\nend",
        "severity": Severity.WARNING,
    },
    {
        "pattern": r"^ip\s+source-route\b",
        "title": "IP source routing enabled",
        "description": "IP source routing allows packets to specify their own route through the network. This is a well-known attack vector and should be disabled.",
        "remediation": "configure terminal\nno ip source-route\nend",
        "rollback": "configure terminal\nip source-route\nend",
        "severity": Severity.WARNING,
        "ref": "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/ipaddr_sla/configuration/xe-16/sla-xe-16-book.html",
    },
    {
        "pattern": r"^ip\s+finger\b",
        "title": "Finger service enabled",
        "description": "The finger service exposes user information and should be disabled.",
        "remediation": "configure terminal\nno ip finger\nend",
        "rollback": "configure terminal\nip finger\nend",
        "severity": Severity.WARNING,
    },
    {
        "pattern": r"^service\s+tcp-small-servers\b",
        "title": "TCP small servers enabled",
        "description": "TCP small servers (echo, chargen, daytime, discard) are unnecessary and present an attack surface.",
        "remediation": "configure terminal\nno service tcp-small-servers\nend",
        "rollback": "configure terminal\nservice tcp-small-servers\nend",
        "severity": Severity.WARNING,
    },
    {
        "pattern": r"^service\s+udp-small-servers\b",
        "title": "UDP small servers enabled",
        "description": "UDP small servers are unnecessary and present an attack surface.",
        "remediation": "configure terminal\nno service udp-small-servers\nend",
        "rollback": "configure terminal\nservice udp-small-servers\nend",
        "severity": Severity.WARNING,
    },
]


class SyntaxLinter(BaseLinter):
    """Version-aware syntax validation for deprecated/removed commands."""

    def __init__(self, vendor: Vendor, os_version: str | None = None):
        self.vendor = vendor
        self.os_version = os_version

    def lint(self, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []

        # Get vendor-specific deprecated commands
        vendor_key = self.vendor.value if isinstance(self.vendor, Vendor) else str(self.vendor)
        deprecated = _DEPRECATED_COMMANDS.get(vendor_key, [])

        for i, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("!") or stripped.startswith("#"):
                continue
            line_num = i + 1

            # Check vendor-specific deprecated commands
            for check in deprecated:
                if re.search(check["pattern"], stripped, re.IGNORECASE):
                    # Version check if applicable
                    if "min_version" in check and self.os_version:
                        if not self._version_gte(self.os_version, check["min_version"]):
                            continue

                    findings.append(self._make_finding(
                        line_start=line_num,
                        line_end=line_num,
                        severity=Severity.WARNING,
                        category=FindingCategory.SYNTAX,
                        title=check["title"],
                        description=check["description"],
                        remediation=check.get("remediation", ""),
                        rollback=check.get("rollback", ""),
                        reference_url=check.get("ref"),
                        config_context=stripped,
                    ))

            # Check universal bad commands (IOS/IOS-XE only)
            if vendor_key in ("cisco_ios", "cisco_iosxe"):
                for check in _UNIVERSAL_BAD_COMMANDS:
                    if re.search(check["pattern"], stripped, re.IGNORECASE):
                        findings.append(self._make_finding(
                            line_start=line_num,
                            line_end=line_num,
                            severity=check.get("severity", Severity.WARNING),
                            category=FindingCategory.SYNTAX,
                            title=check["title"],
                            description=check["description"],
                            remediation=check.get("remediation", ""),
                            rollback=check.get("rollback", ""),
                            reference_url=check.get("ref"),
                            config_context=stripped,
                        ))

        return findings

    @staticmethod
    def _version_gte(actual: str, minimum: str) -> bool:
        """Check if actual version >= minimum version (major.minor comparison)."""
        try:
            actual_parts = [int(x) for x in re.findall(r"\d+", actual)[:2]]
            min_parts = [int(x) for x in re.findall(r"\d+", minimum)[:2]]
            return actual_parts >= min_parts
        except (ValueError, IndexError):
            return True  # Can't determine — assume it applies
