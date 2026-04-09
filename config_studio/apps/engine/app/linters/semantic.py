"""Semantic linter — detects misconfigurations that are syntactically valid
but operationally dangerous (REQ-3.3.3).

Single-device checks only — no external topology or device state required.
"""

from __future__ import annotations

import re
from app.api.schemas import Finding, Severity, FindingCategory, Vendor
from app.linters.base import BaseLinter
from app.parsers.cisco_ios import CiscoIOSParser
from app.parsers.junos import JunOSParser
from app.parsers.base import ParsedConfig


class SemanticLinter(BaseLinter):
    """Semantic analysis: catches dangerous misconfigs that pass syntax checks."""

    def __init__(self, vendor: Vendor):
        self.vendor = vendor

    def lint(self, lines: list[str]) -> list[Finding]:
        config_text = "\n".join(lines)
        vendor_key = self.vendor.value if isinstance(self.vendor, Vendor) else str(self.vendor)

        # Parse config into structured form
        if vendor_key in ("cisco_ios", "cisco_iosxe"):
            parser = CiscoIOSParser()
        elif vendor_key == "junos":
            parser = JunOSParser()
        else:
            return []

        parsed = parser.parse(config_text)
        findings: list[Finding] = []

        findings.extend(self._check_unused_acls(parsed, lines))
        findings.extend(self._check_undefined_references(parsed, lines))
        findings.extend(self._check_vlan_consistency(parsed, lines))
        findings.extend(self._check_ospf_area_consistency(parsed))
        findings.extend(self._check_bgp_peer_groups(parsed, lines))
        findings.extend(self._check_static_route_interfaces(parsed, lines))
        findings.extend(self._check_port_channel_consistency(parsed))
        findings.extend(self._check_acl_shadowing(parsed, lines))

        return findings

    def _check_unused_acls(self, parsed: ParsedConfig, lines: list[str]) -> list[Finding]:
        """ACLs defined but never applied to any interface."""
        findings = []

        # Collect defined ACLs
        defined_acls: dict[str, int] = {}
        for section in parsed.sections:
            if section.section_type in ("acl", "acl_numbered"):
                name = section.name.split()[-1] if section.name else ""
                if name:
                    defined_acls[name] = section.start_line

        # Collect referenced ACLs (in access-group, route-map match, etc.)
        full_text = "\n".join(lines)
        referenced_acls: set[str] = set()
        for m in re.finditer(r"ip access-group\s+(\S+)", full_text):
            referenced_acls.add(m.group(1))
        for m in re.finditer(r"match ip address\s+(\S+)", full_text):
            referenced_acls.add(m.group(1))
        for m in re.finditer(r"match access-group\s+(?:name\s+)?(\S+)", full_text):
            referenced_acls.add(m.group(1))

        for acl_name, line_num in defined_acls.items():
            if acl_name not in referenced_acls:
                findings.append(self._make_finding(
                    line_start=line_num,
                    line_end=line_num,
                    severity=Severity.INFO,
                    category=FindingCategory.BEST_PRACTICE,
                    title=f"ACL '{acl_name}' defined but never applied",
                    description=f"Access list '{acl_name}' is defined but is not referenced by any "
                                "interface access-group, route-map, or other policy. It has no effect.",
                    remediation=f"! If intentional, no action needed. Otherwise:\nconfigure terminal\nno ip access-list extended {acl_name}\nend",
                    rollback=f"! Re-create the ACL definition",
                ))

        return findings

    def _check_undefined_references(self, parsed: ParsedConfig, lines: list[str]) -> list[Finding]:
        """Route-maps, prefix-lists, or community-lists referenced but not defined."""
        findings = []
        full_text = "\n".join(lines)

        # Collect defined route-maps
        defined_route_maps = {s.attributes.get("name", s.name.split()[1] if len(s.name.split()) > 1 else "")
                              for s in parsed.sections if s.section_type == "route_map"}

        # Collect defined prefix-lists
        defined_prefix_lists: set[str] = set()
        for i, line in enumerate(lines):
            m = re.match(r"ip prefix-list\s+(\S+)", line.strip())
            if m:
                defined_prefix_lists.add(m.group(1))

        # Find references to route-maps in BGP config
        for section in parsed.sections:
            if section.section_type == "router_bgp":
                for j, subline in enumerate(section.lines):
                    m = re.search(r"route-map\s+(\S+)\s+(in|out)", subline, re.IGNORECASE)
                    if m:
                        rm_name = m.group(1)
                        if rm_name not in defined_route_maps:
                            findings.append(self._make_finding(
                                line_start=section.start_line + j,
                                line_end=section.start_line + j,
                                severity=Severity.WARNING,
                                category=FindingCategory.BEST_PRACTICE,
                                title=f"Route-map '{rm_name}' referenced but not defined",
                                description=f"BGP config references route-map '{rm_name}' but it is not defined "
                                            "in this config. The route-map will have no effect (implicit deny).",
                                remediation=f"configure terminal\nroute-map {rm_name} permit 10\n ! Add match/set clauses\nend",
                                rollback=f"configure terminal\nno route-map {rm_name}\nend",
                            ))

        # Find references to prefix-lists in route-maps
        for section in parsed.sections:
            if section.section_type == "route_map":
                for j, subline in enumerate(section.lines):
                    m = re.search(r"match ip address prefix-list\s+(\S+)", subline, re.IGNORECASE)
                    if m:
                        pl_name = m.group(1)
                        if pl_name not in defined_prefix_lists:
                            findings.append(self._make_finding(
                                line_start=section.start_line + j,
                                line_end=section.start_line + j,
                                severity=Severity.WARNING,
                                category=FindingCategory.BEST_PRACTICE,
                                title=f"Prefix-list '{pl_name}' referenced but not defined",
                                description=f"Route-map references prefix-list '{pl_name}' but it is not defined.",
                                remediation=f"configure terminal\nip prefix-list {pl_name} seq 10 permit 0.0.0.0/0 le 32\nend",
                                rollback=f"configure terminal\nno ip prefix-list {pl_name}\nend",
                            ))

        return findings

    def _check_vlan_consistency(self, parsed: ParsedConfig, lines: list[str]) -> list[Finding]:
        """VLANs referenced in trunk allowed lists but not defined in VLAN database."""
        findings = []

        # Collect defined VLANs
        defined_vlans: set[int] = set()
        for section in parsed.sections:
            if section.section_type == "vlan":
                vlan_str = section.attributes.get("vlan_id", "")
                for v in self._parse_vlan_range(str(vlan_str)):
                    defined_vlans.add(v)

        if not defined_vlans:
            return findings  # No VLAN database section — can't check

        # Check trunk allowed VLANs
        for section in parsed.sections:
            if section.section_type == "interface":
                trunk_vlans = section.attributes.get("trunk_allowed_vlans")
                if trunk_vlans:
                    for vlan_id in self._parse_vlan_range(trunk_vlans):
                        if vlan_id not in defined_vlans and vlan_id != 1:
                            findings.append(self._make_finding(
                                line_start=section.start_line,
                                line_end=section.end_line,
                                severity=Severity.WARNING,
                                category=FindingCategory.BEST_PRACTICE,
                                title=f"VLAN {vlan_id} in trunk allowed list but not defined",
                                description=f"Interface {section.attributes.get('interface_name', section.name)} "
                                            f"allows VLAN {vlan_id} on its trunk, but VLAN {vlan_id} is not "
                                            "defined in the VLAN database section of this config.",
                                remediation=f"configure terminal\nvlan {vlan_id}\n name VLAN{vlan_id}\nend",
                                rollback=f"configure terminal\nno vlan {vlan_id}\nend",
                            ))

        return findings

    def _check_ospf_area_consistency(self, parsed: ParsedConfig) -> list[Finding]:
        """OSPF area inconsistency — two interfaces sharing a subnet in different areas."""
        findings = []
        ospf_sections = parsed.get_sections("router_ospf")

        for ospf in ospf_sections:
            networks = ospf.attributes.get("networks", [])
            # Group by area — check for overlapping networks across areas
            area_networks: dict[str, list] = {}
            for net in networks:
                area = net.get("area", "0")
                area_networks.setdefault(area, []).append(net)

            # This is a basic check — flag if same network appears in multiple areas
            seen_networks: dict[str, tuple[str, int]] = {}
            for net in networks:
                network_key = net["network"]
                area = net.get("area", "0")
                if network_key in seen_networks and seen_networks[network_key][0] != area:
                    findings.append(self._make_finding(
                        line_start=net["line"],
                        line_end=net["line"],
                        severity=Severity.CRITICAL,
                        category=FindingCategory.BEST_PRACTICE,
                        title="OSPF area inconsistency",
                        description=f"Network {network_key} is assigned to area {area} but was "
                                    f"previously assigned to area {seen_networks[network_key][0]} "
                                    f"(line {seen_networks[network_key][1]}). This will cause OSPF issues.",
                        remediation=f"configure terminal\nrouter ospf {ospf.attributes.get('process_id', '1')}\n"
                                    f" no network {network_key} {net.get('wildcard', '0.0.0.0')} area {area}\n"
                                    f" network {network_key} {net.get('wildcard', '0.0.0.0')} area {seen_networks[network_key][0]}\nend",
                        rollback=f"configure terminal\nrouter ospf {ospf.attributes.get('process_id', '1')}\n"
                                 f" network {network_key} {net.get('wildcard', '0.0.0.0')} area {area}\nend",
                    ))
                else:
                    seen_networks[network_key] = (area, net["line"])

        return findings

    def _check_bgp_peer_groups(self, parsed: ParsedConfig, lines: list[str]) -> list[Finding]:
        """BGP peer-group referenced but not defined."""
        findings = []
        for section in parsed.sections:
            if section.section_type == "router_bgp":
                # Collect defined peer-groups
                defined_groups: set[str] = set()
                group_refs: list[dict] = []

                for subline in section.lines:
                    m = re.match(r"neighbor\s+(\S+)\s+peer-group$", subline.strip())
                    if m:
                        defined_groups.add(m.group(1))
                    m2 = re.match(r"neighbor\s+\S+\s+peer-group\s+(\S+)", subline.strip())
                    if m2:
                        group_refs.append({"name": m2.group(1), "line": subline})

                for ref in section.attributes.get("peer_group_refs", []):
                    pg_name = ref.get("peer_group", "")
                    if pg_name and pg_name not in defined_groups:
                        findings.append(self._make_finding(
                            line_start=ref.get("line", section.start_line),
                            line_end=ref.get("line", section.start_line),
                            severity=Severity.WARNING,
                            category=FindingCategory.BEST_PRACTICE,
                            title=f"BGP peer-group '{pg_name}' referenced but not defined",
                            description=f"A neighbor references peer-group '{pg_name}' but this peer-group "
                                        "is not defined in the BGP configuration.",
                            remediation=f"configure terminal\nrouter bgp {section.attributes.get('asn', '')}\n"
                                        f" neighbor {pg_name} peer-group\nend",
                            rollback=f"configure terminal\nrouter bgp {section.attributes.get('asn', '')}\n"
                                     f" no neighbor {pg_name} peer-group\nend",
                        ))

        return findings

    def _check_static_route_interfaces(self, parsed: ParsedConfig, lines: list[str]) -> list[Finding]:
        """Static routes pointing to interfaces that don't exist in config."""
        findings = []

        # Collect interface names
        interface_names = set()
        for section in parsed.sections:
            if section.section_type == "interface":
                iface = section.attributes.get("interface_name", "")
                if iface:
                    interface_names.add(iface)

        # Check static routes
        for i, line in enumerate(lines):
            m = re.match(r"ip route\s+\S+\s+\S+\s+(\S+)", line.strip())
            if m:
                next_hop = m.group(1)
                # If next-hop looks like an interface name (not an IP)
                if not re.match(r"\d+\.\d+\.\d+\.\d+", next_hop):
                    if next_hop not in interface_names:
                        findings.append(self._make_finding(
                            line_start=i + 1,
                            line_end=i + 1,
                            severity=Severity.WARNING,
                            category=FindingCategory.BEST_PRACTICE,
                            title=f"Static route points to non-existent interface '{next_hop}'",
                            description=f"A static route uses interface '{next_hop}' as the next hop, "
                                        "but this interface is not defined in the config.",
                            remediation=f"configure terminal\nno {line.strip()}\n! Correct the next-hop interface or IP\nend",
                            rollback=f"configure terminal\n{line.strip()}\nend",
                        ))

        return findings

    def _check_port_channel_consistency(self, parsed: ParsedConfig) -> list[Finding]:
        """Inconsistent speed/duplex across interfaces in the same port-channel."""
        findings = []

        # Group interfaces by channel-group
        channel_groups: dict[str, list] = {}
        for section in parsed.sections:
            if section.section_type == "interface":
                cg = section.attributes.get("channel_group")
                if cg:
                    channel_groups.setdefault(cg, []).append(section)

        for cg_id, members in channel_groups.items():
            speeds = {}
            duplexes = {}
            for iface in members:
                speed = iface.attributes.get("speed", "auto")
                duplex = iface.attributes.get("duplex", "auto")
                iname = iface.attributes.get("interface_name", iface.name)
                speeds[iname] = speed
                duplexes[iname] = duplex

            unique_speeds = set(speeds.values())
            if len(unique_speeds) > 1:
                findings.append(self._make_finding(
                    line_start=members[0].start_line,
                    line_end=members[-1].end_line,
                    severity=Severity.WARNING,
                    category=FindingCategory.BEST_PRACTICE,
                    title=f"Inconsistent speed in port-channel {cg_id}",
                    description=f"Port-channel {cg_id} members have different speed settings: "
                                + ", ".join(f"{k}={v}" for k, v in speeds.items()),
                    remediation=f"! Set all members to the same speed:\n"
                                + "\n".join(f"interface {name}\n speed {list(unique_speeds)[0]}" for name in speeds),
                    rollback="! Restore original speed settings on each interface",
                ))

        return findings

    def _check_acl_shadowing(self, parsed: ParsedConfig, lines: list[str]) -> list[Finding]:
        """Overlapping or shadowed ACL entries (permit/deny order issues)."""
        findings = []

        for section in parsed.sections:
            if section.section_type != "acl":
                continue

            entries = []
            for j, subline in enumerate(section.lines[1:], start=1):  # Skip the ACL definition line
                parsed_entry = self._parse_acl_entry(subline.strip())
                if parsed_entry:
                    parsed_entry["line"] = section.start_line + j
                    parsed_entry["index"] = j
                    entries.append(parsed_entry)

            for idx, entry in enumerate(entries):
                later_entries = entries[idx + 1:]
                if not later_entries:
                    continue

                shadowed_count = sum(1 for later in later_entries if self._acl_entry_shadows(entry, later))
                if shadowed_count:
                    findings.append(self._make_finding(
                        line_start=entry["line"],
                        line_end=entry["line"],
                        severity=Severity.WARNING,
                        category=FindingCategory.BEST_PRACTICE,
                        title=f"Potential ACL shadowing in {section.name}",
                        description=f"'{entry['action']} {entry['rule']}' is broad enough to match before "
                                    f"{shadowed_count} later ACL entr{'y' if shadowed_count == 1 else 'ies'}, so those rules may never be evaluated.",
                        remediation="! Reorder ACL entries — place more specific rules before broad rules",
                        rollback="! Restore original ACL entry order",
                    ))
                    break  # Only flag once per ACL

        return findings

    @staticmethod
    def _parse_acl_entry(line: str) -> dict | None:
        match = re.match(r"(permit|deny)\s+(\S+)\s+(.+)", line, re.IGNORECASE)
        if not match:
            return None

        return {
            "action": match.group(1).lower(),
            "protocol": match.group(2).lower(),
            "rule": f"{match.group(2)} {match.group(3)}",
            "tokens": match.group(3).lower().split(),
        }

    @classmethod
    def _acl_entry_shadows(cls, earlier: dict, later: dict) -> bool:
        if earlier["protocol"] not in {"ip", later["protocol"]}:
            return False

        earlier_tokens = earlier.get("tokens", [])
        later_tokens = later.get("tokens", [])
        if len(earlier_tokens) < 2 or len(later_tokens) < 2:
            return False

        earlier_src, earlier_dst = earlier_tokens[0], earlier_tokens[1]
        later_src, later_dst = later_tokens[0], later_tokens[1]

        earlier_is_any_any = earlier_src == "any" and earlier_dst == "any"
        if earlier_is_any_any and cls._acl_has_only_non_narrowing_trailers(earlier_tokens[2:]):
            return True

        same_match_scope = (
            earlier["protocol"] == later["protocol"]
            and earlier_src == later_src
            and earlier_dst == later_dst
            and len(earlier_tokens) <= len(later_tokens)
        )
        if same_match_scope:
            return earlier_tokens == later_tokens[:len(earlier_tokens)]

        return False

    @staticmethod
    def _acl_has_only_non_narrowing_trailers(tokens: list[str]) -> bool:
        """Return True when trailing ACL tokens add logging/commentary but do not narrow match scope."""
        if not tokens:
            return True

        non_narrowing_tokens = {"log", "log-input"}
        return all(token in non_narrowing_tokens for token in tokens)

    @staticmethod
    def _parse_vlan_range(vlan_str: str) -> list[int]:
        """Parse VLAN range string like '10,20,30-40' into list of VLAN IDs."""
        vlans = []
        for part in vlan_str.replace(" ", "").split(","):
            if "-" in part:
                try:
                    start, end = part.split("-", 1)
                    vlans.extend(range(int(start), int(end) + 1))
                except ValueError:
                    pass
            else:
                try:
                    vlans.append(int(part))
                except ValueError:
                    pass
        return vlans
