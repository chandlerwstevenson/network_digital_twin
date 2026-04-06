from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass

from app.api.schemas import Finding, FindingCategory, Severity, Vendor
from app.parsers.base import ParsedConfig, ParsedSection
from app.parsers.cisco_ios import CiscoIOSParser
from app.parsers.junos import JunOSParser


@dataclass
class DeviceModel:
    name: str
    vendor: str
    parsed: ParsedConfig
    interfaces: list[dict]
    ospf_areas: dict[str, str]
    bgp_neighbors: list[dict]


def correlate_configs(configs: list[dict]) -> tuple[list[Finding], list[dict]]:
    devices: list[DeviceModel] = []
    for idx, item in enumerate(configs, start=1):
        model = _build_device_model(item, idx)
        if model:
            devices.append(model)

    findings: list[Finding] = []
    links = _infer_links(devices)

    findings.extend(_check_ospf_area_mismatch(links))
    findings.extend(_check_mtu_mismatch(links))
    findings.extend(_check_trunk_vlan_mismatch(links))
    findings.extend(_check_bgp_neighbor_consistency(devices))

    return findings, links


def _build_device_model(item: dict, idx: int) -> DeviceModel | None:
    config_text = item.get("config_text", "")
    if not config_text.strip():
        return None

    vendor = item.get("vendor")
    vendor_key = vendor.value if isinstance(vendor, Vendor) else vendor
    if not vendor_key:
        from app.parsers.detector import detect_vendor

        vendor_key = detect_vendor(config_text).vendor.value

    if vendor_key in ("cisco_ios", "cisco_iosxe"):
        parser = CiscoIOSParser()
    elif vendor_key == "junos":
        parser = JunOSParser()
    else:
        return None

    parsed = parser.parse(config_text)
    hostname = item.get("hostname") or parsed.hostname or f"device-{idx}"
    interfaces = _extract_interfaces(parsed)
    ospf_areas = _extract_ospf_areas(parsed, interfaces)
    for iface in interfaces:
        iface["ospf_area"] = ospf_areas.get(iface.get("network"))
    bgp_neighbors = _extract_bgp_neighbors(parsed)

    return DeviceModel(
        name=hostname,
        vendor=vendor_key,
        parsed=parsed,
        interfaces=interfaces,
        ospf_areas=ospf_areas,
        bgp_neighbors=bgp_neighbors,
    )


def _extract_interfaces(parsed: ParsedConfig) -> list[dict]:
    interfaces: list[dict] = []
    for section in parsed.get_interfaces():
        iface_name = section.attributes.get("interface_name") or section.name
        ip_cidr = _interface_network(section)
        interfaces.append(
            {
                "name": iface_name,
                "line_start": section.start_line,
                "line_end": section.end_line,
                "description": section.attributes.get("description", ""),
                "network": ip_cidr,
                "ip": _interface_ip(section),
                "mtu": str(section.attributes.get("mtu", "")).strip() or None,
                "trunk_allowed_vlans": section.attributes.get("trunk_allowed_vlans"),
            }
        )
    return interfaces


def _interface_ip(section: ParsedSection) -> str | None:
    ip_address = section.attributes.get("ip_address")
    if not ip_address:
        return None
    return str(ip_address).split("/")[0]


def _interface_network(section: ParsedSection) -> str | None:
    ip_address = section.attributes.get("ip_address")
    subnet_mask = section.attributes.get("subnet_mask")
    if not ip_address:
        return None

    try:
        if "/" in str(ip_address):
            return str(ipaddress.ip_interface(str(ip_address)).network)
        if subnet_mask:
            return str(ipaddress.ip_interface(f"{ip_address}/{subnet_mask}").network)
    except ValueError:
        return None
    return None


def _extract_ospf_areas(parsed: ParsedConfig, interfaces: list[dict]) -> dict[str, str]:
    area_map: dict[str, str] = {}
    interface_networks = {iface["name"]: iface.get("network") for iface in interfaces}

    for ospf in parsed.get_sections("router_ospf"):
        for entry in ospf.attributes.get("networks", []):
            network = entry.get("network")
            area = str(entry.get("area", "0"))
            wildcard = entry.get("wildcard")
            if network and wildcard:
                try:
                    net = ipaddress.IPv4Network((network, wildcard_to_netmask(wildcard)), strict=False)
                    area_map[str(net)] = area
                except ValueError:
                    pass

        for entry in ospf.attributes.get("area_interfaces", []):
            iface = entry.get("interface")
            area = str(entry.get("area", "0"))
            network = interface_networks.get(iface)
            if network:
                area_map[network] = area

    return area_map


def _extract_bgp_neighbors(parsed: ParsedConfig) -> list[dict]:
    neighbors: list[dict] = []
    for bgp in parsed.get_sections("router_bgp"):
        for neighbor in bgp.attributes.get("neighbors", []):
            neighbors.append(
                {
                    "peer_ip": neighbor.get("ip"),
                    "remote_as": str(neighbor.get("remote_as")) if neighbor.get("remote_as") else None,
                    "line": neighbor.get("line", bgp.start_line),
                    "local_as": str(bgp.attributes.get("asn")) if bgp.attributes.get("asn") else None,
                }
            )
    return neighbors


def _infer_links(devices: list[DeviceModel]) -> list[dict]:
    links: list[dict] = []
    seen: set[tuple[str, str, str, str]] = set()

    for left in devices:
        for right in devices:
            if left.name == right.name:
                continue

            for left_iface in left.interfaces:
                for right_iface in right.interfaces:
                    if left_iface.get("network") and left_iface.get("network") == right_iface.get("network"):
                        key = tuple(sorted([left.name, right.name]) + sorted([left_iface["name"], right_iface["name"]]))
                        if key in seen:
                            continue
                        seen.add(key)
                        links.append(
                            {
                                "kind": "shared_subnet",
                                "network": left_iface["network"],
                                "left_device": left.name,
                                "left_interface": left_iface,
                                "right_device": right.name,
                                "right_interface": right_iface,
                                "confidence": "high",
                                "label": f"{left.name}:{left_iface['name']} ↔ {right.name}:{right_iface['name']}",
                            }
                        )

            for left_iface in left.interfaces:
                if not left_iface.get("description"):
                    continue
                if right.name.lower() not in left_iface["description"].lower():
                    continue
                for right_iface in right.interfaces:
                    if left.name.lower() in (right_iface.get("description") or "").lower():
                        key = tuple(sorted([left.name, right.name]) + sorted([left_iface["name"], right_iface["name"]]))
                        if key in seen:
                            continue
                        seen.add(key)
                        links.append(
                            {
                                "kind": "description_inferred",
                                "network": left_iface.get("network") or right_iface.get("network"),
                                "left_device": left.name,
                                "left_interface": left_iface,
                                "right_device": right.name,
                                "right_interface": right_iface,
                                "confidence": "medium",
                                "label": f"{left.name}:{left_iface['name']} ↔ {right.name}:{right_iface['name']}",
                            }
                        )
    return links


def _check_ospf_area_mismatch(links: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for link in links:
        network = link.get("network")
        if not network:
            continue
        left_area = link["left_interface"].get("ospf_area")
        right_area = link["right_interface"].get("ospf_area")
        if left_area and right_area and left_area != right_area:
            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    line_start=link["left_interface"]["line_start"],
                    line_end=link["right_interface"]["line_end"],
                    severity=Severity.CRITICAL,
                    category=FindingCategory.BEST_PRACTICE,
                    title="Cross-device OSPF area mismatch",
                    description=(
                        f"{link['left_device']} and {link['right_device']} share subnet {network}, but the inferred link is "
                        f"assigned to different OSPF areas ({left_area} vs {right_area}). Adjacency will not form."
                    ),
                    remediation=(
                        f"Align OSPF area assignment on both devices for subnet {network}.\n"
                        f"- {link['left_device']} interface {link['left_interface']['name']}: use area {right_area} or move both sides to the intended area.\n"
                        f"- {link['right_device']} interface {link['right_interface']['name']}: verify peer expectation before change."
                    ),
                    rollback="Restore the previous OSPF area statements on both devices if the adjacency was intentionally segmented.",
                    compliance_tags=["operational-risk"],
                    config_context=f"Inferred link: {link['label']} ({link['confidence']} confidence)",
                )
            )
    return findings


def _check_mtu_mismatch(links: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for link in links:
        left_mtu = link["left_interface"].get("mtu")
        right_mtu = link["right_interface"].get("mtu")
        if left_mtu and right_mtu and left_mtu != right_mtu:
            findings.append(
                Finding(
                    id=str(uuid.uuid4()),
                    line_start=link["left_interface"]["line_start"],
                    line_end=link["right_interface"]["line_end"],
                    severity=Severity.WARNING,
                    category=FindingCategory.BEST_PRACTICE,
                    title="Cross-device MTU mismatch",
                    description=(
                        f"Inferred link {link['label']} has mismatched MTU settings ({left_mtu} vs {right_mtu}). "
                        "This can break routing adjacencies or black-hole larger packets."
                    ),
                    remediation=(
                        f"Normalize MTU on both sides of the link. Recommended next step: confirm intended transport MTU, "
                        f"then set {link['left_device']} {link['left_interface']['name']} and {link['right_device']} {link['right_interface']['name']} to the same value."
                    ),
                    rollback="Restore the prior MTU value on the side that was changed if traffic degrades after alignment.",
                    compliance_tags=["operational-risk"],
                    config_context=f"Inferred link: {link['label']} ({link['confidence']} confidence)",
                )
            )
    return findings


def _check_trunk_vlan_mismatch(links: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    for link in links:
        left_vlans = _parse_vlan_set(link["left_interface"].get("trunk_allowed_vlans"))
        right_vlans = _parse_vlan_set(link["right_interface"].get("trunk_allowed_vlans"))
        if not left_vlans or not right_vlans or left_vlans == right_vlans:
            continue
        missing_left = sorted(right_vlans - left_vlans)
        missing_right = sorted(left_vlans - right_vlans)
        findings.append(
            Finding(
                id=str(uuid.uuid4()),
                line_start=link["left_interface"]["line_start"],
                line_end=link["right_interface"]["line_end"],
                severity=Severity.CRITICAL,
                category=FindingCategory.BEST_PRACTICE,
                title="Cross-device trunk VLAN mismatch",
                description=(
                    f"Inferred trunk {link['label']} allows different VLAN sets. "
                    f"{link['left_device']} only: {', '.join(map(str, missing_right)) or 'none'}; "
                    f"{link['right_device']} only: {', '.join(map(str, missing_left)) or 'none'}."
                ),
                remediation="Align the allowed VLAN list on both trunk interfaces before deployment so the same VLANs traverse both sides of the link.",
                rollback="Restore the prior allowed VLAN list on the modified side if the mismatch was intentional for maintenance staging.",
                compliance_tags=["operational-risk"],
                config_context=f"Inferred link: {link['label']} ({link['confidence']} confidence)",
            )
        )
    return findings


def _check_bgp_neighbor_consistency(devices: list[DeviceModel]) -> list[Finding]:
    findings: list[Finding] = []
    ip_to_device: dict[str, tuple[str, str | None]] = {}
    for device in devices:
        for iface in device.interfaces:
            if iface.get("ip"):
                ip_to_device[iface["ip"]] = (device.name, iface["name"])

    device_map = {device.name: device for device in devices}

    for device in devices:
        local_ips = {iface.get("ip") for iface in device.interfaces if iface.get("ip")}
        for neighbor in device.bgp_neighbors:
            peer_ip = neighbor.get("peer_ip")
            if not peer_ip or peer_ip not in ip_to_device:
                continue
            peer_device_name, peer_interface = ip_to_device[peer_ip]
            if peer_device_name == device.name:
                continue
            peer_device = device_map.get(peer_device_name)
            reverse_match = False
            if peer_device:
                for peer_neighbor in peer_device.bgp_neighbors:
                    if peer_neighbor.get("peer_ip") in local_ips:
                        reverse_match = True
                        break
            if not reverse_match:
                findings.append(
                    Finding(
                        id=str(uuid.uuid4()),
                        line_start=neighbor.get("line", 1),
                        line_end=neighbor.get("line", 1),
                        severity=Severity.CRITICAL,
                        category=FindingCategory.BEST_PRACTICE,
                        title="Cross-device BGP peer mismatch",
                        description=(
                            f"{device.name} peers to {peer_ip}, which belongs to {peer_device_name}:{peer_interface}, "
                            f"but {peer_device_name} does not show a reciprocal BGP neighbor pointing back to {device.name}."
                        ),
                        remediation=(
                            f"Verify the intended BGP peering pair and add or correct the reciprocal neighbor statement on {peer_device_name}. "
                            f"If the peer should target a loopback instead, update {device.name} to the correct IP."
                        ),
                        rollback="Restore the original neighbor statement if the peer address was intentionally staged and the remote side has not been updated yet.",
                        compliance_tags=["operational-risk"],
                        config_context=f"Detected via cross-config IP normalization between {device.name} and {peer_device_name}.",
                    )
                )
    return findings


def _parse_vlan_set(raw: str | None) -> set[int]:
    if not raw:
        return set()
    vlans: set[int] = set()
    for part in str(raw).replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                vlans.update(range(int(start), int(end) + 1))
            except ValueError:
                continue
        else:
            try:
                vlans.add(int(part))
            except ValueError:
                continue
    return vlans


def wildcard_to_netmask(wildcard: str) -> str:
    octets = [255 - int(part) for part in wildcard.split(".")]
    return ".".join(str(o) for o in octets)
