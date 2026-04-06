"""Compliance tagger — maps findings to regulatory frameworks.

Tags each finding with applicable compliance frameworks:
GxP, SOX Section 404, PCI-DSS 4.0, HIPAA, NIST 800-53.
"""

from __future__ import annotations

from app.api.schemas import Finding


# Mapping of finding keywords/patterns to compliance frameworks
_COMPLIANCE_MAP: dict[str, list[str]] = {
    # Password / credential issues
    "plaintext password": ["PCI-DSS-8.2.1", "NIST-800-53-IA-5", "HIPAA-164.312(d)", "SOX-404"],
    "weak password": ["PCI-DSS-8.2.1", "NIST-800-53-IA-5", "HIPAA-164.312(d)"],
    "type 7": ["PCI-DSS-8.2.1", "NIST-800-53-IA-5"],
    "enable password": ["CIS-Cisco-IOS", "DISA-STIG-NET"],

    # Encryption issues
    "weak encryption": ["PCI-DSS-4.1", "NIST-800-53-SC-13", "HIPAA-164.312(e)(1)"],
    "des": ["PCI-DSS-4.1", "NIST-800-53-SC-13"],
    "3des": ["PCI-DSS-4.1", "NIST-800-53-SC-13"],
    "telnet": ["PCI-DSS-4.1", "NIST-800-53-SC-8", "HIPAA-164.312(e)(1)"],
    "http server": ["PCI-DSS-4.1", "NIST-800-53-SC-8"],

    # Access control
    "no aaa": ["PCI-DSS-8.1", "NIST-800-53-IA-2", "HIPAA-164.312(d)", "SOX-404"],
    "no authentication": ["PCI-DSS-8.1", "NIST-800-53-IA-2", "HIPAA-164.312(d)"],
    "auxiliary port": ["CIS-Cisco-IOS", "DISA-STIG-NET", "NIST-800-53-IA-2"],
    "exec-timeout": ["CIS-Cisco-IOS", "NIST-800-53-AC-12"],

    # SNMP
    "snmp community": ["PCI-DSS-2.1", "NIST-800-53-CM-6", "CIS-Cisco-IOS"],
    "default community": ["PCI-DSS-2.1", "NIST-800-53-CM-6"],

    # Network security
    "source routing": ["CIS-Cisco-IOS", "NIST-800-53-SC-7"],
    "copp": ["CIS-Cisco-IOS", "NIST-800-53-SC-5"],

    # Operational risk
    "lost on reload": ["GxP-Change-Control", "SOX-404-IT-Controls"],
    "ospf area": ["operational-risk"],
    "bgp peer": ["operational-risk"],
    "acl shadow": ["operational-risk", "PCI-DSS-1.1"],
    "vlan": ["PCI-DSS-1.3", "NIST-800-53-SC-7"],
}


class ComplianceTagger:
    """Enrich findings with compliance framework tags."""

    def tag_findings(self, findings: list[Finding]) -> list[Finding]:
        """Add compliance tags to findings based on their content."""
        for finding in findings:
            existing_tags = set(finding.compliance_tags)

            # Match against compliance map
            search_text = f"{finding.title} {finding.description}".lower()
            for keyword, tags in _COMPLIANCE_MAP.items():
                if keyword.lower() in search_text:
                    existing_tags.update(tags)

            finding.compliance_tags = sorted(existing_tags)

        return findings
