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

        def first_meaningful_line() -> int:
            for idx, raw in enumerate(lines, start=1):
                stripped = raw.strip()
                if stripped and not stripped.startswith("!"):
                    return idx
            return 1

        has_aaa = False
        has_http_server = False
        has_https_server = False
        has_copp = False
        has_enable_secret = False
        http_server_line: int | None = None
        aaa_anchor_line: int | None = None
        copp_anchor_line: int | None = None
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
                http_server_line = line_num
            if re.search(r"^ip http secure-server\b", stripped):
                has_https_server = True

            # --- AAA detection ---
            if stripped.startswith("aaa new-model") or stripped.startswith("aaa authentication"):
                has_aaa = True
                aaa_anchor_line = line_num
            elif aaa_anchor_line is None and (stripped.startswith("line vty") or stripped.startswith("line con") or stripped.startswith("username ") or stripped.startswith("enable ")):
                aaa_anchor_line = line_num

            # --- CoPP detection ---
            if "control-plane" in stripped.lower() or "copp" in stripped.lower():
                has_copp = True
                copp_anchor_line = line_num
            elif copp_anchor_line is None and stripped.startswith("interface "):
                copp_anchor_line = line_num

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
            http_line = http_server_line or first_meaningful_line()
            findings.append(self._make_finding(
                line_start=http_line,
                line_end=http_line,
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
            aaa_line = aaa_anchor_line or first_meaningful_line()
            findings.append(self._make_finding(
                line_start=aaa_line,
                line_end=aaa_line,
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
            copp_line = copp_anchor_line or first_meaningful_line()
            findings.append(self._make_finding(
                line_start=copp_line,
                line_end=copp_line,
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

        def first_meaningful_line() -> int:
            for idx, raw in enumerate(lines, start=1):
                stripped = raw.strip()
                if stripped and not stripped.startswith("#"):
                    return idx
            return 1

        has_ssh = False
        has_telnet = False
        has_https_web_mgmt = False
        has_http_web_mgmt = False
        has_aaa = False
        http_mgmt_line: int | None = None
        aaa_anchor_line: int | None = None
        mgmt_service_lines: list[int] = []
        public_interface_lines: list[tuple[str, int, str]] = []
        hierarchy_stack: list[str] = []

        def stack_endswith(*segments: str) -> bool:
            if len(hierarchy_stack) < len(segments):
                return False
            return [segment.lower() for segment in hierarchy_stack[-len(segments):]] == [segment.lower() for segment in segments]

        for i, line in enumerate(lines):
            stripped = line.strip()
            line_num = i + 1
            lower = stripped.lower()

            if stripped == "}":
                if hierarchy_stack:
                    hierarchy_stack.pop()
                continue

            hierarchical_block = stripped.endswith("{")
            block_name = stripped[:-1].strip() if hierarchical_block else ""
            block_name_lower = block_name.lower()

            # Plaintext passwords in JunOS
            if re.search(r"plain-text-password", stripped):
                findings.append(self._make_finding(
                    line_start=line_num,
                    line_end=line_num,
                    severity=Severity.CRITICAL,
                    category=FindingCategory.SECURITY,
                    title="Plaintext password in JunOS config",
                    description="A password is configured in plaintext. Use encrypted-password instead.",
                    remediation="delete system login user <user> authentication plain-text-password\nset system login user <user> authentication encrypted-password <hash>",
                    rollback="set system login user <user> authentication plain-text-password",
                    compliance_tags=["PCI-DSS-8.2.1", "NIST-800-53-IA-5"],
                ))

            # Default SNMP communities in JunOS
            if re.search(r"community\s+(public|private)(\s|;|$)", stripped, re.IGNORECASE):
                community_match = re.search(r"community\s+(public|private)", stripped, re.IGNORECASE)
                community = community_match.group(1) if community_match else "public"
                findings.append(self._make_finding(
                    line_start=line_num,
                    line_end=line_num,
                    severity=Severity.CRITICAL,
                    category=FindingCategory.SECURITY,
                    title="Default SNMP community string in JunOS",
                    description=f"Default SNMP community '{community}' detected. Change to a strong, unique string and restrict it.",
                    remediation=f"delete snmp community {community}\nset snmp community <strong-string> authorization read-only\nset snmp community <strong-string> clients <trusted-prefix>",
                    rollback=f"set snmp community {community} authorization read-only",
                    compliance_tags=["PCI-DSS-2.1", "CIS-Juniper", "NIST-800-53-CM-6"],
                ))
                mgmt_service_lines.append(line_num)

            telnet_hierarchical = stack_endswith("system", "services") and lower == "telnet;"
            if "system services telnet" in lower or telnet_hierarchical:
                has_telnet = True
                mgmt_service_lines.append(line_num)
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
                    reference_url="https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/telnet-edit-system-services.html",
                ))

            ssh_hierarchical = stack_endswith("system", "services") and lower == "ssh;"
            if "system services ssh" in lower or ssh_hierarchical:
                has_ssh = True
                mgmt_service_lines.append(line_num)

            http_hierarchical = stack_endswith("system", "services", "web-management") and (lower == "http;" or block_name_lower == "http")
            if "system services web-management http" in lower or http_hierarchical:
                has_http_web_mgmt = True
                http_mgmt_line = line_num
                mgmt_service_lines.append(line_num)

            https_hierarchical = stack_endswith("system", "services", "web-management") and (lower == "https;" or block_name_lower == "https")
            if "system services web-management https" in lower or https_hierarchical:
                has_https_web_mgmt = True
                mgmt_service_lines.append(line_num)

            if any(token in lower for token in ["system tacplus-server", "system radius-server", "authentication-order [ tacplus", "authentication-order [ radius", "authentication-order tacplus", "authentication-order radius"]):
                has_aaa = True
                aaa_anchor_line = line_num
            elif stack_endswith("system") and block_name_lower in {"tacplus-server", "radius-server"}:
                has_aaa = True
                aaa_anchor_line = line_num
            elif aaa_anchor_line is None and ("system login user" in lower or "system services ssh" in lower or ssh_hierarchical or stripped.startswith("system {") or stripped.startswith("set system ")):
                aaa_anchor_line = line_num

            if lower.startswith("set interfaces ") and " family inet address " in lower:
                m = re.match(r"set interfaces\s+(\S+)(?:\s+unit\s+\S+)?\s+family inet address\s+([^\s;]+)", stripped, re.IGNORECASE)
                if m:
                    interface_name = m.group(1)
                    ip_text = m.group(2).split("/")[0]
                    if self._is_public_ipv4(ip_text):
                        public_interface_lines.append((interface_name, line_num, ip_text))

            if hierarchy_stack and len(hierarchy_stack) >= 4 and hierarchy_stack[0].lower() == "interfaces" and hierarchy_stack[-2].lower().startswith("unit ") and hierarchy_stack[-1].lower() == "family inet" and lower.startswith("address "):
                interface_name = hierarchy_stack[1] if len(hierarchy_stack) > 1 else None
                address_match = re.match(r"address\s+([^\s;]+)", stripped, re.IGNORECASE)
                if interface_name and address_match:
                    ip_text = address_match.group(1).split("/")[0]
                    if self._is_public_ipv4(ip_text):
                        public_interface_lines.append((interface_name, line_num, ip_text))

            if hierarchical_block:
                hierarchy_stack.append(block_name)

        if has_http_web_mgmt and not has_https_web_mgmt:
            http_line = http_mgmt_line or next((line for line in mgmt_service_lines if line), first_meaningful_line())
            findings.append(self._make_finding(
                line_start=http_line,
                line_end=http_line,
                severity=Severity.WARNING,
                category=FindingCategory.SECURITY,
                title="JunOS HTTP management enabled without HTTPS",
                description="JunOS web management is enabled over HTTP but HTTPS is not configured. Management traffic may be exposed in cleartext.",
                remediation="delete system services web-management http\nset system services web-management https system-generated-certificate",
                rollback="set system services web-management http",
                compliance_tags=["PCI-DSS-4.1", "NIST-800-53-SC-8"],
                reference_url="https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/web-management-edit-system.html",
            ))

        if not has_aaa:
            aaa_line = aaa_anchor_line or first_meaningful_line()
            findings.append(self._make_finding(
                line_start=aaa_line,
                line_end=aaa_line,
                severity=Severity.WARNING,
                category=FindingCategory.SECURITY,
                title="No TACACS+ or RADIUS configuration detected in JunOS config",
                description="No TACACS+ or RADIUS configuration was found. Centralized AAA is missing, so administrative authentication appears to rely on local accounts only.",
                remediation="set system tacplus-server <server-ip> secret <secret>\nset system authentication-order [ tacplus password ]",
                rollback="delete system tacplus-server <server-ip>\nset system authentication-order password",
                compliance_tags=["CIS-Juniper", "DISA-STIG", "NIST-800-53-IA-2", "PCI-DSS-8.1"],
                reference_url="https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/user-access-tacacs-authentication.html",
            ))

        if public_interface_lines and any([has_ssh, has_telnet, has_http_web_mgmt, has_https_web_mgmt, mgmt_service_lines]):
            for interface_name, line_num, ip_text in public_interface_lines:
                findings.append(self._make_finding(
                    line_start=line_num,
                    line_end=line_num,
                    severity=Severity.INFO,
                    category=FindingCategory.SECURITY,
                    title=f"Management plane may be exposed on {interface_name}",
                    description=f"Interface {interface_name} has public-looking address {ip_text} while JunOS management services are enabled elsewhere in the config. Verify SSH, SNMP, or web management are not exposed to untrusted networks.",
                    remediation=f"set firewall family inet filter PROTECT-RE management-term from source-address <trusted-prefix>\nset firewall family inet filter PROTECT-RE management-term then accept\nset interfaces {interface_name} unit 0 family inet filter input PROTECT-RE",
                    rollback=f"delete interfaces {interface_name} unit 0 family inet filter input PROTECT-RE",
                    compliance_tags=["PCI-DSS-4.1", "NIST-800-53-SC-7"],
                    reference_url="https://www.rfc-editor.org/rfc/rfc5737",
                ))

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
