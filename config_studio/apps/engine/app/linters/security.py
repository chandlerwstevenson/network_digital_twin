"""Security linter — REQ-3.3.4 security-specific checks.

Detects: plaintext passwords, weak hashing, management plane exposure,
missing CoPP, default SNMP communities, weak encryption, missing AAA,
auxiliary port, HTTP without HTTPS, console timeout issues.
"""

from __future__ import annotations

import re
from app.api.schemas import Finding, Severity, FindingCategory, Vendor
from app.linters.base import BaseLinter


class SecurityLinter(BaseLinter):
    """Security-focused checks for network configs."""

    def __init__(self, vendor: Vendor):
        self.vendor = vendor

    def lint(self, lines: list[str]) -> list[Finding]:
        vendor_key = self.vendor.value if isinstance(self.vendor, Vendor) else str(self.vendor)

        if vendor_key in ("cisco_ios", "cisco_iosxe"):
            return self._lint_cisco(lines)
        elif vendor_key == "junos":
            return self._lint_junos(lines)
        return []

    def _lint_cisco(self, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        full_text = "\n".join(lines)

        has_aaa = False
        has_http_server = False
        has_https_server = False
        has_copp = False
        has_enable_secret = False
        in_line_section = False
        in_interface_section = False
        current_line_type = ""
        current_interface = ""
        line_start = 0
        interface_start = 0
        has_exec_timeout = False
        interface_has_public_ip = False
        interface_has_mgmt_plane = False

        for i, line in enumerate(lines):
            stripped = line.strip()
            line_num = i + 1

            # Track state
            if stripped.startswith("interface "):
                if in_interface_section and interface_has_public_ip and interface_has_mgmt_plane:
                    findings.append(self._make_finding(
                        line_start=interface_start,
                        line_end=line_num - 1,
                        severity=Severity.INFO,
                        category=FindingCategory.SECURITY,
                        title=f"Management plane may be exposed on {current_interface}",
                        description=f"Interface {current_interface} appears to have a public IP and also permits management-plane services. Verify this interface is not exposed to untrusted networks.",
                        remediation=f"configure terminal\ninterface {current_interface}\n ! Restrict management plane with ACLs or disable unnecessary management services\nend",
                        rollback=f"configure terminal\ninterface {current_interface}\n ! Restore prior interface management exposure if intentional\nend",
                        compliance_tags=["PCI-DSS-4.1", "NIST-800-53-SC-7"],
                        reference_url="https://www.rfc-editor.org/rfc/rfc5737",
                    ))
                in_interface_section = True
                current_interface = stripped.split(None, 1)[1] if len(stripped.split(None, 1)) > 1 else stripped
                interface_start = line_num
                interface_has_public_ip = False
                interface_has_mgmt_plane = False
            elif in_interface_section and not line.startswith(" ") and stripped and not stripped.startswith("!"):
                if interface_has_public_ip and interface_has_mgmt_plane:
                    findings.append(self._make_finding(
                        line_start=interface_start,
                        line_end=line_num - 1,
                        severity=Severity.INFO,
                        category=FindingCategory.SECURITY,
                        title=f"Management plane may be exposed on {current_interface}",
                        description=f"Interface {current_interface} appears to have a public IP and also permits management-plane services. Verify this interface is not exposed to untrusted networks.",
                        remediation=f"configure terminal\ninterface {current_interface}\n ! Restrict management plane with ACLs or disable unnecessary management services\nend",
                        rollback=f"configure terminal\ninterface {current_interface}\n ! Restore prior interface management exposure if intentional\nend",
                        compliance_tags=["PCI-DSS-4.1", "NIST-800-53-SC-7"],
                        reference_url="https://www.rfc-editor.org/rfc/rfc5737",
                    ))
                in_interface_section = False

            if stripped.startswith("line "):
                in_line_section = True
                current_line_type = stripped
                line_start = line_num
                has_exec_timeout = False
            elif in_line_section and not line.startswith(" ") and stripped and not stripped.startswith("!"):
                # Exiting line section — check if we had exec-timeout
                if "line aux" in current_line_type or "line con" in current_line_type:
                    if not has_exec_timeout:
                        findings.append(self._make_finding(
                            line_start=line_start,
                            line_end=line_num - 1,
                            severity=Severity.WARNING,
                            category=FindingCategory.SECURITY,
                            title=f"No exec-timeout on {current_line_type}",
                            description=f"The {current_line_type} section has no exec-timeout configured. "
                                        "Idle sessions will never terminate, creating a security risk.",
                            remediation=f"configure terminal\n{current_line_type}\n exec-timeout 10 0\nend",
                            rollback=f"configure terminal\n{current_line_type}\n no exec-timeout\nend",
                            compliance_tags=["CIS-Cisco-IOS", "NIST-800-53-AC-12"],
                            reference_url="https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_cfg/configuration/xe-16/sec-user-config-xe-16-book/sec-setting_line_cmds.html",
                        ))
                in_line_section = False

            if in_interface_section and stripped.startswith("ip address "):
                m = re.match(r"ip address\s+(\S+)\s+(\S+)", stripped)
                if m and self._is_public_ipv4(m.group(1)):
                    interface_has_public_ip = True

            if in_interface_section and any(token in stripped.lower() for token in ["ip access-group", "snmp-server", "ip http", "ssh", "management"]):
                interface_has_mgmt_plane = True

            if in_line_section and "exec-timeout" in stripped:
                has_exec_timeout = True
                # Check for unreasonably long timeout
                m = re.match(r"exec-timeout\s+(\d+)\s*(\d*)", stripped)
                if m:
                    minutes = int(m.group(1))
                    if minutes > 30:
                        findings.append(self._make_finding(
                            line_start=line_num,
                            line_end=line_num,
                            severity=Severity.INFO,
                            category=FindingCategory.SECURITY,
                            title="Long exec-timeout",
                            description=f"exec-timeout is set to {minutes} minutes. Consider reducing to 10 minutes or less.",
                            remediation=f"configure terminal\n{current_line_type}\n exec-timeout 10 0\nend",
                            rollback=f"configure terminal\n{current_line_type}\n exec-timeout {minutes} {m.group(2) or '0'}\nend",
                        ))

            # --- Plaintext passwords (type 0) ---
            if re.search(r"password\s+0\s+", stripped) or re.search(r"^password\s+(?!7\s)(?!5\s)(?!8\s)(?!9\s)\S+", stripped):
                if "password 7 " not in stripped and "password 5 " not in stripped:
                    findings.append(self._make_finding(
                        line_start=line_num,
                        line_end=line_num,
                        severity=Severity.CRITICAL,
                        category=FindingCategory.SECURITY,
                        title="Plaintext password detected",
                        description="A password is stored in plaintext (type 0). This is visible to anyone who can read the config.",
                        remediation="configure terminal\nservice password-encryption\nend\n! Then re-enter the password to use type 7 encryption (minimum)\n! Better: use 'enable algorithm-type scrypt secret' for type 9",
                        rollback="! Cannot rollback — password was already visible",
                        compliance_tags=["PCI-DSS-8.2.1", "NIST-800-53-IA-5", "CIS-Cisco-IOS"],
                        config_context=self._redact_password(stripped),
                        reference_url="https://www.cisco.com/c/en/us/support/docs/security-vpn/password-encryption/12091-15.html",
                    ))

            # --- Type 7 weak encryption ---
            if re.search(r"password\s+7\s+", stripped):
                findings.append(self._make_finding(
                    line_start=line_num,
                    line_end=line_num,
                    severity=Severity.WARNING,
                    category=FindingCategory.SECURITY,
                    title="Weak password encryption (type 7)",
                    description="Type 7 password encryption is trivially reversible. Use type 5 (MD5), type 8 (PBKDF2), or type 9 (scrypt) instead.",
                    remediation="! Re-enter the password using a stronger hash:\n! enable algorithm-type scrypt secret <password>",
                    rollback="! Re-enter original password with type 7",
                    compliance_tags=["PCI-DSS-8.2.1", "NIST-800-53-IA-5"],
                    config_context=self._redact_password(stripped),
                    reference_url="https://www.cisco.com/c/en/us/support/docs/security-vpn/password-encryption/12091-15.html",
                ))

            # --- Enable password without secret ---
            if stripped.startswith("enable password"):
                findings.append(self._make_finding(
                    line_start=line_num,
                    line_end=line_num,
                    severity=Severity.CRITICAL,
                    category=FindingCategory.SECURITY,
                    title="'enable password' used instead of 'enable secret'",
                    description="'enable password' uses weak or no encryption. Use 'enable secret' with scrypt (type 9) for strong hashing.",
                    remediation="configure terminal\nno enable password\nenable algorithm-type scrypt secret <new-password>\nend",
                    rollback="configure terminal\nno enable secret\nenable password <old-password>\nend",
                    compliance_tags=["CIS-Cisco-IOS", "DISA-STIG"],
                    reference_url="https://www.cisco.com/c/en/us/support/docs/security-vpn/password-encryption/12091-15.html",
                ))
            if stripped.startswith("enable secret"):
                has_enable_secret = True

            # --- Default SNMP communities ---
            if re.search(r"snmp-server community\s+(public|private)\s", stripped, re.IGNORECASE):
                community = re.search(r"community\s+(\S+)", stripped).group(1)
                findings.append(self._make_finding(
                    line_start=line_num,
                    line_end=line_num,
                    severity=Severity.CRITICAL,
                    category=FindingCategory.SECURITY,
                    title=f"Default SNMP community string: '{community}'",
                    description=f"SNMP community string '{community}' is a well-known default. This allows unauthorized SNMP access.",
                    remediation=f"configure terminal\nno snmp-server community {community}\nsnmp-server community <strong-string> RO <acl-name>\nend",
                    rollback=f"configure terminal\nno snmp-server community <new-string>\nsnmp-server community {community}\nend",
                    compliance_tags=["PCI-DSS-2.1", "CIS-Cisco-IOS", "NIST-800-53-CM-6"],
                    reference_url="https://www.cisco.com/c/en/us/support/docs/ip/simple-network-management-protocol-snmp/7282-12.html",
                ))

            # --- Weak encryption algorithms ---
            if re.search(r"(des|3des|md5)", stripped, re.IGNORECASE) and "crypto" in stripped.lower():
                if "ipsec" in stripped.lower() or "isakmp" in stripped.lower() or "ikev" in stripped.lower():
                    weak_algo = re.search(r"(des|3des|md5)", stripped, re.IGNORECASE).group(1)
                    findings.append(self._make_finding(
                        line_start=line_num,
                        line_end=line_num,
                        severity=Severity.WARNING,
                        category=FindingCategory.SECURITY,
                        title=f"Weak encryption algorithm: {weak_algo.upper()}",
                        description=f"{weak_algo.upper()} is considered weak/broken. Use AES-256 and SHA-256 or higher.",
                        remediation="! Replace with AES-256-GCM and SHA-384/512 in your crypto config",
                        rollback="! Restore original crypto configuration",
                        compliance_tags=["PCI-DSS-4.1", "NIST-800-53-SC-13"],
                        config_context=stripped,
                        reference_url="https://www.cisco.com/c/en/us/support/docs/security-vpn/ipsec-negotiation-ike-protocols/14106-howdoi.html",
                    ))

            # --- HTTP server without HTTPS ---
            if re.search(r"^ip http server\b", stripped):
                has_http_server = True
            if re.search(r"^ip http secure-server\b", stripped):
                has_https_server = True

            # --- AAA detection ---
            if stripped.startswith("aaa new-model") or stripped.startswith("aaa authentication"):
                has_aaa = True

            # --- CoPP detection ---
            if "control-plane" in stripped.lower() or "copp" in stripped.lower():
                has_copp = True

            # --- Auxiliary port with no auth ---
            if in_line_section and "line aux" in current_line_type:
                if stripped == "no login" or stripped == "login":
                    if stripped == "no login":
                        findings.append(self._make_finding(
                            line_start=line_num,
                            line_end=line_num,
                            severity=Severity.CRITICAL,
                            category=FindingCategory.SECURITY,
                            title="Auxiliary port has no authentication",
                            description="The auxiliary port is accessible without any authentication. This is a physical access risk.",
                            remediation=f"configure terminal\n{current_line_type}\n login local\n transport input none\nend",
                            rollback=f"configure terminal\n{current_line_type}\n no login\nend",
                            compliance_tags=["CIS-Cisco-IOS", "DISA-STIG", "NIST-800-53-IA-2"],
                        ))

            # --- Telnet enabled ---
            if in_line_section and "line vty" in current_line_type:
                if stripped == "transport input telnet" or stripped == "transport input all":
                    findings.append(self._make_finding(
                        line_start=line_num,
                        line_end=line_num,
                        severity=Severity.WARNING,
                        category=FindingCategory.SECURITY,
                        title="Telnet enabled on VTY lines",
                        description="Telnet transmits credentials in cleartext. Use SSH only.",
                        remediation=f"configure terminal\n{current_line_type}\n transport input ssh\nend",
                        rollback=f"configure terminal\n{current_line_type}\n transport input telnet ssh\nend",
                        compliance_tags=["PCI-DSS-4.1", "CIS-Cisco-IOS", "DISA-STIG"],
                    ))

        # --- Post-scan global checks ---
        if has_http_server and not has_https_server:
            findings.append(self._make_finding(
                line_start=1,
                line_end=1,
                severity=Severity.WARNING,
                category=FindingCategory.SECURITY,
                title="HTTP server enabled without HTTPS",
                description="The HTTP server is enabled but HTTPS (secure-server) is not. Management traffic is unencrypted.",
                remediation="configure terminal\nno ip http server\nip http secure-server\nend",
                rollback="configure terminal\nip http server\nno ip http secure-server\nend",
                compliance_tags=["PCI-DSS-4.1", "NIST-800-53-SC-8"],
                reference_url="https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_http/configuration/xe-16/sec-usr-http-xe-16-book.html",
            ))

        if not has_aaa:
            findings.append(self._make_finding(
                line_start=1,
                line_end=1,
                severity=Severity.WARNING,
                category=FindingCategory.SECURITY,
                title="No AAA configuration detected",
                description="No AAA (TACACS+/RADIUS) configuration found. AAA provides centralized authentication, "
                            "authorization, and accounting. Without it, all auth is local-only.",
                remediation="configure terminal\naaa new-model\naaa authentication login default group tacacs+ local\naaa authorization exec default group tacacs+ local\nend",
                rollback="configure terminal\nno aaa new-model\nend",
                compliance_tags=["CIS-Cisco-IOS", "DISA-STIG", "NIST-800-53-IA-2", "PCI-DSS-8.1"],
                reference_url="https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_aaa/configuration/xe-16/sec-usr-aaa-xe-16-book.html",
            ))

        if not has_copp:
            findings.append(self._make_finding(
                line_start=1,
                line_end=1,
                severity=Severity.INFO,
                category=FindingCategory.SECURITY,
                title="No Control Plane Policing (CoPP) detected",
                description="No CoPP configuration found. CoPP protects the management plane from DoS attacks.",
                remediation="! Configure CoPP — see Cisco CoPP design guide for your platform",
                rollback="! Remove CoPP policy-map from control-plane",
                compliance_tags=["CIS-Cisco-IOS", "NIST-800-53-SC-5"],
                reference_url="https://www.cisco.com/c/en/us/about/security-center/control-plane-policing.html",
            ))

        return findings

    def _lint_junos(self, lines: list[str]) -> list[Finding]:
        findings: list[Finding] = []
        full_text = "\n".join(lines)

        has_ssh = False
        has_telnet = False

        for i, line in enumerate(lines):
            stripped = line.strip()
            line_num = i + 1

            # Plaintext passwords in JunOS
            if re.search(r"plain-text-password", stripped):
                findings.append(self._make_finding(
                    line_start=line_num,
                    line_end=line_num,
                    severity=Severity.CRITICAL,
                    category=FindingCategory.SECURITY,
                    title="Plaintext password in JunOS config",
                    description="A password is configured in plaintext. Use encrypted-password instead.",
                    remediation="! Replace with encrypted-password hash",
                    rollback="! N/A",
                    compliance_tags=["PCI-DSS-8.2.1", "NIST-800-53-IA-5"],
                ))

            # Default SNMP communities in JunOS
            if re.search(r"community\s+(public|private)", stripped, re.IGNORECASE):
                findings.append(self._make_finding(
                    line_start=line_num,
                    line_end=line_num,
                    severity=Severity.CRITICAL,
                    category=FindingCategory.SECURITY,
                    title="Default SNMP community string in JunOS",
                    description="Default SNMP community detected. Change to a strong, unique string.",
                    remediation="delete snmp community public\nset snmp community <strong-string> authorization read-only",
                    rollback="set snmp community public authorization read-only",
                    compliance_tags=["PCI-DSS-2.1", "CIS-Juniper"],
                ))

            # Telnet service
            if "system services telnet" in stripped or "set system services telnet" in stripped:
                has_telnet = True
                findings.append(self._make_finding(
                    line_start=line_num,
                    line_end=line_num,
                    severity=Severity.WARNING,
                    category=FindingCategory.SECURITY,
                    title="Telnet service enabled",
                    description="Telnet transmits credentials in cleartext. Disable telnet and use SSH.",
                    remediation="delete system services telnet\nset system services ssh",
                    rollback="set system services telnet",
                    compliance_tags=["PCI-DSS-4.1", "CIS-Juniper"],
                ))

            if "system services ssh" in stripped:
                has_ssh = True

        return findings

    @staticmethod
    def _redact_password(line: str) -> str:
        """Redact actual password values from config context."""
        return re.sub(r"(password\s+(?:0|7|5|8|9)?\s*)\S+", r"\1****", line)

    @staticmethod
    def _is_public_ipv4(ip: str) -> bool:
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
            return False
        octets = [int(x) for x in ip.split('.')]
        if octets[0] == 10:
            return False
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return False
        if octets[0] == 192 and octets[1] == 168:
            return False
        if octets[0] == 127:
            return False
        if octets[0] == 169 and octets[1] == 254:
            return False
        return True
