"""Cisco IOS / IOS-XE config parser.

Parses running-config into structured sections for linting.
Uses indentation-based hierarchy (IOS configs use single-space indent
for sub-commands under a parent like 'interface' or 'router').
"""

from __future__ import annotations

import re
from app.parsers.base import BaseParser, ParsedConfig, ParsedSection


# Section-starting commands (these begin a new hierarchical block)
_SECTION_STARTERS = {
    "interface": "interface",
    "router ospf": "router_ospf",
    "router bgp": "router_bgp",
    "router eigrp": "router_eigrp",
    "router rip": "router_rip",
    "ip access-list": "acl",
    "access-list": "acl_numbered",
    "vlan": "vlan",
    "line": "line",
    "route-map": "route_map",
    "ip prefix-list": "prefix_list",
    "ip community-list": "community_list",
    "class-map": "class_map",
    "policy-map": "policy_map",
    "crypto": "crypto",
    "snmp-server": "snmp",
    "ntp": "ntp",
    "aaa": "aaa",
    "ip dhcp pool": "dhcp_pool",
    "key chain": "key_chain",
}


class CiscoIOSParser(BaseParser):
    """Parser for Cisco IOS 12.x/15.x and IOS-XE 16.x/17.x configs."""

    def supports(self, vendor: str, os_version: str | None = None) -> bool:
        return vendor in ("cisco_ios", "cisco_iosxe")

    def parse(self, config_text: str) -> ParsedConfig:
        lines = config_text.splitlines()
        config = ParsedConfig(raw_lines=lines)

        # Extract hostname and version
        for line in lines:
            if line.startswith("hostname "):
                config.hostname = line.split(None, 1)[1].strip()
            elif line.startswith("version "):
                config.os_version = line.split(None, 1)[1].strip()

        # Parse into sections
        current_section: ParsedSection | None = None
        for i, line in enumerate(lines):
            stripped = line.strip()
            line_num = i + 1

            # Skip comments and empty lines
            if not stripped or stripped.startswith("!"):
                if current_section:
                    # End of section on blank/comment line at root level
                    if not line.startswith(" ") and not line.startswith("\t"):
                        config.sections.append(current_section)
                        current_section = None
                continue

            # Check if this starts a new section
            section_type = self._match_section(stripped)
            if section_type and not line.startswith(" "):
                # Save previous section
                if current_section:
                    config.sections.append(current_section)

                name = stripped
                current_section = ParsedSection(
                    section_type=section_type,
                    name=name,
                    start_line=line_num,
                    end_line=line_num,
                    lines=[stripped],
                    attributes=self._parse_section_header(section_type, stripped),
                )
            elif current_section and (line.startswith(" ") or line.startswith("\t")):
                # Sub-command within current section
                current_section.lines.append(stripped)
                current_section.end_line = line_num
                self._parse_subcommand(current_section, stripped, line_num)
            else:
                # Global command
                if current_section:
                    config.sections.append(current_section)
                    current_section = None
                config.global_commands.append((line_num, stripped))

        # Don't forget last section
        if current_section:
            config.sections.append(current_section)

        return config

    def _match_section(self, line: str) -> str | None:
        """Match a line to a known section type."""
        lower = line.lower()
        for prefix, section_type in _SECTION_STARTERS.items():
            if lower.startswith(prefix):
                return section_type
        return None

    def _parse_section_header(self, section_type: str, line: str) -> dict:
        """Extract key attributes from a section header."""
        attrs = {}
        if section_type == "interface":
            parts = line.split(None, 1)
            if len(parts) > 1:
                attrs["interface_name"] = parts[1]
                # Extract interface type and number
                m = re.match(r"([A-Za-z-]+)(\S*)", parts[1])
                if m:
                    attrs["interface_type"] = m.group(1)
                    attrs["interface_number"] = m.group(2)
        elif section_type == "router_ospf":
            m = re.search(r"router ospf\s+(\d+)", line)
            if m:
                attrs["process_id"] = m.group(1)
        elif section_type == "router_bgp":
            m = re.search(r"router bgp\s+(\d+)", line)
            if m:
                attrs["asn"] = m.group(1)
        elif section_type == "vlan":
            m = re.search(r"vlan\s+(\d+(?:-\d+)?(?:,\d+)*)", line)
            if m:
                attrs["vlan_id"] = m.group(1)
        elif section_type == "route_map":
            parts = line.split()
            if len(parts) >= 3:
                attrs["name"] = parts[1]
                attrs["action"] = parts[2] if len(parts) > 2 else None
                attrs["sequence"] = parts[3] if len(parts) > 3 else None
        return attrs

    def _parse_subcommand(self, section: ParsedSection, cmd: str, line_num: int):
        """Parse a sub-command and update section attributes."""
        lower = cmd.lower()
        attrs = section.attributes

        if section.section_type == "interface":
            if lower.startswith("ip address"):
                m = re.match(r"ip address\s+(\S+)\s+(\S+)", cmd, re.IGNORECASE)
                if m:
                    attrs["ip_address"] = m.group(1)
                    attrs["subnet_mask"] = m.group(2)
            elif lower.startswith("description"):
                attrs["description"] = cmd.split(None, 1)[1] if len(cmd.split(None, 1)) > 1 else ""
            elif "shutdown" == lower:
                attrs["shutdown"] = True
            elif "no shutdown" == lower:
                attrs["shutdown"] = False
            elif lower.startswith("switchport mode"):
                attrs["switchport_mode"] = cmd.split()[-1]
            elif lower.startswith("switchport trunk allowed vlan"):
                attrs["trunk_allowed_vlans"] = cmd.split("vlan")[-1].strip()
            elif lower.startswith("switchport trunk native vlan"):
                attrs["native_vlan"] = cmd.split()[-1]
            elif lower.startswith("ip access-group"):
                parts = cmd.split()
                direction = parts[-1] if parts[-1] in ("in", "out") else None
                acl_name = parts[1] if len(parts) > 1 else None
                if direction and acl_name:
                    attrs.setdefault("access_groups", {})[direction] = acl_name
            elif lower.startswith("storm-control"):
                attrs["has_storm_control"] = True
            elif lower.startswith("spanning-tree"):
                attrs["has_spanning_tree"] = True
            elif lower.startswith("channel-group"):
                m = re.search(r"channel-group\s+(\d+)", cmd)
                if m:
                    attrs["channel_group"] = m.group(1)
            elif lower.startswith("speed"):
                attrs["speed"] = cmd.split()[-1]
            elif lower.startswith("duplex"):
                attrs["duplex"] = cmd.split()[-1]
            elif lower.startswith("mtu"):
                attrs["mtu"] = cmd.split()[-1]

        elif section.section_type in ("router_ospf",):
            if lower.startswith("network"):
                m = re.match(r"network\s+(\S+)\s+(\S+)\s+area\s+(\S+)", cmd, re.IGNORECASE)
                if m:
                    attrs.setdefault("networks", []).append({
                        "network": m.group(1),
                        "wildcard": m.group(2),
                        "area": m.group(3),
                        "line": line_num,
                    })

        elif section.section_type == "router_bgp":
            if lower.startswith("neighbor") and "remote-as" in lower:
                m = re.match(r"neighbor\s+(\S+)\s+remote-as\s+(\d+)", cmd, re.IGNORECASE)
                if m:
                    attrs.setdefault("neighbors", []).append({
                        "ip": m.group(1),
                        "remote_as": m.group(2),
                        "line": line_num,
                    })
            elif lower.startswith("neighbor") and "peer-group" in lower:
                parts = cmd.split()
                if len(parts) >= 3:
                    attrs.setdefault("peer_group_refs", []).append({
                        "name_or_ip": parts[1],
                        "peer_group": parts[3] if len(parts) > 3 else parts[2],
                        "line": line_num,
                    })
