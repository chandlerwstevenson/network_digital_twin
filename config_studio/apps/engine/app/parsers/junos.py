"""Juniper JunOS config parser — supports both set and hierarchical formats."""

from __future__ import annotations

import re
from app.parsers.base import BaseParser, ParsedConfig, ParsedSection


class JunOSParser(BaseParser):
    """Parser for JunOS configs in set-format and hierarchical/curly-brace format."""

    def supports(self, vendor: str, os_version: str | None = None) -> bool:
        return vendor == "junos"

    def parse(self, config_text: str) -> ParsedConfig:
        lines = config_text.splitlines()
        config = ParsedConfig(raw_lines=lines, vendor="junos")

        # Detect format
        is_set_format = self._is_set_format(lines)

        if is_set_format:
            self._parse_set_format(config, lines)
        else:
            self._parse_hierarchical(config, lines)

        return config

    def _is_set_format(self, lines: list[str]) -> bool:
        set_lines = sum(1 for l in lines[:50] if l.strip().startswith("set "))
        brace_lines = sum(1 for l in lines[:50] if "{" in l or "}" in l)
        return set_lines > brace_lines

    def _parse_set_format(self, config: ParsedConfig, lines: list[str]):
        """Parse JunOS set-format config."""
        sections_map: dict[str, ParsedSection] = {}

        for i, line in enumerate(lines):
            stripped = line.strip()
            line_num = i + 1

            if not stripped or stripped.startswith("#"):
                continue

            if stripped.startswith("set system host-name"):
                config.hostname = stripped.split()[-1]

            if stripped.startswith("set "):
                parts = stripped[4:].split()
                if not parts:
                    continue

                # Group by top-level section
                section_key = parts[0]
                if len(parts) > 1 and section_key in ("protocols", "interfaces", "routing-options",
                                                        "firewall", "policy-options", "security",
                                                        "system", "vlans", "snmp"):
                    subsection = parts[1] if len(parts) > 1 else ""
                    full_key = f"{section_key} {subsection}"

                    section_type = self._map_section_type(section_key, subsection)

                    if full_key not in sections_map:
                        sections_map[full_key] = ParsedSection(
                            section_type=section_type,
                            name=full_key,
                            start_line=line_num,
                            end_line=line_num,
                            lines=[stripped],
                            attributes=self._extract_set_attrs(section_type, parts),
                        )
                    else:
                        sec = sections_map[full_key]
                        sec.lines.append(stripped)
                        sec.end_line = line_num
                        self._update_set_attrs(sec, parts, line_num)
                else:
                    config.global_commands.append((line_num, stripped))

        config.sections = list(sections_map.values())

    def _parse_hierarchical(self, config: ParsedConfig, lines: list[str]):
        """Parse JunOS hierarchical/curly-brace format."""
        path_stack: list[str] = []
        sections_map: dict[str, ParsedSection] = {}
        current_section_key: str | None = None

        for i, line in enumerate(lines):
            stripped = line.strip()
            line_num = i + 1

            if not stripped or stripped.startswith("/*") or stripped.startswith("*/"):
                continue

            # Track hierarchy
            if stripped.endswith("{"):
                name = stripped.rstrip("{ ").strip()
                path_stack.append(name)

                if len(path_stack) <= 2:
                    section_key = " ".join(path_stack)
                    section_type = self._map_section_type(
                        path_stack[0] if path_stack else "",
                        path_stack[1] if len(path_stack) > 1 else "",
                    )
                    if section_key not in sections_map:
                        sections_map[section_key] = ParsedSection(
                            section_type=section_type,
                            name=section_key,
                            start_line=line_num,
                            end_line=line_num,
                            lines=[],
                        )
                    current_section_key = section_key

            elif stripped == "}":
                if path_stack:
                    path_stack.pop()
                current_section_key = " ".join(path_stack[:2]) if path_stack else None

            else:
                # Content line
                if stripped.startswith("host-name"):
                    m = re.search(r"host-name\s+(\S+);?", stripped)
                    if m:
                        config.hostname = m.group(1).rstrip(";")

                if current_section_key and current_section_key in sections_map:
                    sec = sections_map[current_section_key]
                    sec.lines.append(stripped)
                    sec.end_line = line_num
                    self._parse_hierarchical_line(sec, path_stack, stripped, line_num)
                else:
                    config.global_commands.append((line_num, stripped))

        config.sections = list(sections_map.values())

    def _map_section_type(self, top: str, sub: str) -> str:
        mapping = {
            ("interfaces",): "interface",
            ("protocols", "ospf"): "router_ospf",
            ("protocols", "bgp"): "router_bgp",
            ("firewall",): "acl",
            ("policy-options",): "policy_options",
            ("vlans",): "vlan",
            ("system",): "system",
            ("snmp",): "snmp",
            ("routing-options",): "routing_options",
            ("security",): "security",
        }
        for keys, stype in mapping.items():
            if len(keys) == 2 and top == keys[0] and sub == keys[1]:
                return stype
            elif len(keys) == 1 and top == keys[0]:
                return stype
        return top

    def _extract_set_attrs(self, section_type: str, parts: list[str]) -> dict:
        attrs: dict = {}
        if section_type == "interface" and len(parts) > 1:
            attrs["interface_name"] = parts[1]
        elif section_type == "router_ospf":
            attrs.setdefault("areas", [])
        elif section_type == "router_bgp":
            attrs.setdefault("neighbors", [])
        return attrs

    def _update_set_attrs(self, sec: ParsedSection, parts: list[str], line_num: int):
        """Update section attributes from a set command."""
        full_cmd = " ".join(parts)

        if sec.section_type == "interface":
            if "address" in full_cmd:
                m = re.search(r"address\s+(\S+)", full_cmd)
                if m:
                    sec.attributes["ip_address"] = m.group(1)
            if "description" in full_cmd:
                m = re.search(r"description\s+(.+)", full_cmd)
                if m:
                    sec.attributes["description"] = m.group(1).strip('"')

        elif sec.section_type == "router_ospf":
            if "area" in full_cmd and "interface" in full_cmd:
                m = re.search(r"area\s+(\S+)\s+interface\s+(\S+)", full_cmd)
                if m:
                    sec.attributes.setdefault("area_interfaces", []).append({
                        "area": m.group(1),
                        "interface": m.group(2),
                        "line": line_num,
                    })

        elif sec.section_type == "router_bgp":
            if "neighbor" in full_cmd:
                m = re.search(r"neighbor\s+(\S+)", full_cmd)
                if m:
                    sec.attributes.setdefault("neighbors", []).append({
                        "ip": m.group(1),
                        "line": line_num,
                    })

    def _parse_hierarchical_line(self, sec: ParsedSection, path: list[str],
                                  line: str, line_num: int):
        """Parse a content line within hierarchical format."""
        clean = line.rstrip(";").strip()
        full_path = "/".join(path)

        if sec.section_type == "router_ospf" and "area" in full_path:
            if "interface" in clean:
                m = re.search(r"interface\s+(\S+)", clean)
                if m:
                    area = next((p for p in path if re.match(r"\d+\.\d+\.\d+\.\d+", p)), None)
                    sec.attributes.setdefault("area_interfaces", []).append({
                        "area": area,
                        "interface": m.group(1),
                        "line": line_num,
                    })
