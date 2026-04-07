"""Auto-detect vendor and OS version from config content."""

from __future__ import annotations

import re
from app.api.schemas import Vendor, VendorDetection


def detect_vendor(config_text: str) -> VendorDetection:
    """Detect vendor, OS version, and hostname from raw config text.

    Uses header patterns, command syntax, and structural cues to identify
    the platform. Returns confidence level so the UI can prompt for manual
    override when detection is ambiguous.
    """
    text = config_text.strip()
    first_500 = text[:2000]  # Most header info is at the top

    # --- Cisco IOS-XE detection ---
    # IOS-XE configs typically have "IOS-XE" in version line or "Cisco IOS XE"
    iosxe_patterns = [
        r"Cisco IOS[ -]XE Software",
        r"version\s+1[67]\.\d+",  # IOS-XE uses 16.x, 17.x
        r"license boot level",  # Common in IOS-XE
    ]
    for pat in iosxe_patterns:
        if re.search(pat, first_500, re.IGNORECASE):
            version = _extract_version(first_500, r"version\s+(1[67]\.\d+\S*)")
            hostname = _extract_hostname_ios(text)
            return VendorDetection(
                vendor=Vendor.CISCO_IOSXE,
                os_version=version,
                confidence=0.9,
                hostname=hostname,
            )

    # --- Cisco IOS detection ---
    ios_patterns = [
        r"Cisco IOS Software",
        r"version\s+1[25]\.\d+",  # IOS uses 12.x, 15.x
        r"^hostname\s+\S+",
        r"^enable secret",
        r"^service timestamps",
    ]
    ios_score = sum(1 for p in ios_patterns if re.search(p, first_500, re.MULTILINE | re.IGNORECASE))
    if ios_score >= 2:
        version = _extract_version(first_500, r"version\s+(1[25]\.\d+\S*)")
        hostname = _extract_hostname_ios(text)
        return VendorDetection(
            vendor=Vendor.CISCO_IOS,
            os_version=version,
            confidence=min(0.5 + ios_score * 0.15, 0.95),
            hostname=hostname,
        )

    # --- JunOS detection ---
    junos_patterns = [
        r"^set\s+",  # set-format commands
        r"^system\s*\{",  # hierarchical format
        r"protocols\s*\{",
        r"routing-options\s*\{",
        r"## Last changed:",  # JunOS config header
        r"version\s+\d+\.\d+R",  # JunOS version format
    ]
    junos_score = sum(1 for p in junos_patterns if re.search(p, first_500, re.MULTILINE))
    if junos_score >= 2:
        version = _extract_version(first_500, r"version\s+(\d+\.\d+R\S*)")
        hostname = _extract_hostname_junos(text)
        return VendorDetection(
            vendor=Vendor.JUNOS,
            os_version=version,
            confidence=min(0.5 + junos_score * 0.15, 0.95),
            hostname=hostname,
        )

    # --- Fallback: deeper IOS heuristic ---
    if re.search(r"^(hostname\s+\S+|interface|router|ip route|access-list|line\s+vty|line\s+con|line\s+aux|ip http\s+server|snmp-server|aaa\s+new-model)\b", text, re.MULTILINE):
        hostname = _extract_hostname_ios(text)
        return VendorDetection(
            vendor=Vendor.CISCO_IOS,
            os_version=None,
            confidence=0.4,
            hostname=hostname,
        )

    return VendorDetection(vendor=Vendor.UNKNOWN, confidence=0.0)


def _extract_version(text: str, pattern: str) -> str | None:
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(1) if m else None


def _extract_hostname_ios(text: str) -> str | None:
    m = re.search(r"^hostname\s+(\S+)", text, re.MULTILINE)
    return m.group(1) if m else None


def _extract_hostname_junos(text: str) -> str | None:
    # set format
    m = re.search(r"^set system host-name\s+(\S+)", text, re.MULTILINE)
    if m:
        return m.group(1)
    # hierarchical format
    m = re.search(r"host-name\s+(\S+);", text)
    return m.group(1) if m else None
