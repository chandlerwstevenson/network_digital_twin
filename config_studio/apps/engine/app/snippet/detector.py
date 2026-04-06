"""Snippet mode detection — auto-detect partial configs (REQ-3.8).

Heuristics:
- No "version" header line
- Under 50 lines (non-empty, non-comment)
- Starts mid-hierarchy (e.g., "interface", "router bgp")
"""

from __future__ import annotations

import re
from app.api.schemas import SnippetInfo


# Patterns that indicate a config snippet (starts mid-hierarchy)
_SNIPPET_STARTERS = [
    (r"^interface\s+", "interface"),
    (r"^router\s+ospf", "router_ospf"),
    (r"^router\s+bgp", "router_bgp"),
    (r"^router\s+eigrp", "router_eigrp"),
    (r"^ip access-list", "acl"),
    (r"^route-map\s+", "route_map"),
    (r"^line\s+", "line"),
    (r"^vlan\s+\d", "vlan"),
    (r"^crypto\s+", "crypto"),
    (r"^policy-map\s+", "policy_map"),
    (r"^class-map\s+", "class_map"),
    # JunOS set format snippets
    (r"^set\s+interfaces\s+", "interface"),
    (r"^set\s+protocols\s+ospf", "router_ospf"),
    (r"^set\s+protocols\s+bgp", "router_bgp"),
    (r"^set\s+firewall\s+", "acl"),
    (r"^set\s+policy-options\s+", "policy_options"),
]


def detect_snippet(config_text: str, context_hint: str | None = None) -> SnippetInfo:
    """Detect whether the input is a config snippet or full config.

    Returns snippet info including detected section and what checks
    should be suppressed.
    """
    lines = config_text.strip().splitlines()
    non_empty = [l for l in lines if l.strip() and not l.strip().startswith("!") and not l.strip().startswith("#")]

    if not non_empty:
        return SnippetInfo(is_snippet=True, detected_section=context_hint)

    # Heuristic 1: Has a version header = full config
    has_version = any(
        re.match(r"^(version\s+\d|## Last changed|!.*Software)", l.strip(), re.IGNORECASE)
        for l in lines[:20]
    )
    if has_version and len(non_empty) > 50:
        return SnippetInfo(is_snippet=False)

    # Heuristic 2: Under 50 meaningful lines
    is_short = len(non_empty) < 50

    # Heuristic 3: Starts mid-hierarchy
    first_meaningful = non_empty[0].strip() if non_empty else ""
    detected_section = context_hint
    starts_mid_hierarchy = False

    for pattern, section in _SNIPPET_STARTERS:
        if re.match(pattern, first_meaningful, re.IGNORECASE):
            starts_mid_hierarchy = True
            if not detected_section:
                detected_section = section
            break

    is_snippet = (not has_version and is_short) or (not has_version and starts_mid_hierarchy)

    # Determine external references (things the snippet needs from full config)
    external_refs = _find_external_references(non_empty) if is_snippet else []

    # Determine which check categories to suppress in snippet mode
    suppressed = []
    if is_snippet:
        suppressed = [
            "Missing AAA configuration (requires global context)",
            "Missing NTP configuration (requires global context)",
            "Missing CoPP (requires global context)",
            "Missing enable secret (requires global context)",
        ]

    return SnippetInfo(
        is_snippet=is_snippet,
        detected_section=detected_section,
        suppressed_checks=suppressed,
        external_references=external_refs,
    )


def _find_external_references(lines: list[str]) -> list[str]:
    """Find references to things defined outside this snippet."""
    refs = []

    for line in lines:
        stripped = line.strip()

        # Route-map references
        m = re.search(r"route-map\s+(\S+)\s+(in|out)", stripped, re.IGNORECASE)
        if m:
            refs.append(f"This config references route-map '{m.group(1)}' — ensure it is defined in your full config")

        # ACL references
        m = re.search(r"ip access-group\s+(\S+)", stripped, re.IGNORECASE)
        if m:
            refs.append(f"This config references ACL '{m.group(1)}' — ensure it is defined in your full config")

        # Prefix-list references
        m = re.search(r"prefix-list\s+(\S+)", stripped, re.IGNORECASE)
        if m and "ip prefix-list" not in stripped:
            refs.append(f"This config references prefix-list '{m.group(1)}' — ensure it is defined in your full config")

        # Peer-group references
        m = re.search(r"peer-group\s+(\S+)", stripped, re.IGNORECASE)
        if m and not re.match(r"neighbor\s+\S+\s+peer-group$", stripped):
            refs.append(f"This config references peer-group '{m.group(1)}' — ensure it is defined in your full config")

    return list(set(refs))  # Deduplicate
