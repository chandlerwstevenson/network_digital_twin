"""Base parser interface for all vendor config parsers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ParsedSection:
    """A parsed section of a network config."""
    section_type: str  # e.g. "interface", "router_ospf", "router_bgp", "acl", "vlan"
    name: str  # e.g. "GigabitEthernet0/1", "ospf 1", "65001"
    start_line: int
    end_line: int
    lines: list[str] = field(default_factory=list)
    attributes: dict = field(default_factory=dict)
    children: list[ParsedSection] = field(default_factory=list)


@dataclass
class ParsedConfig:
    """Full parsed representation of a network config."""
    hostname: str | None = None
    vendor: str | None = None
    os_version: str | None = None
    sections: list[ParsedSection] = field(default_factory=list)
    global_commands: list[tuple[int, str]] = field(default_factory=list)  # (line_num, command)
    raw_lines: list[str] = field(default_factory=list)

    def get_sections(self, section_type: str) -> list[ParsedSection]:
        return [s for s in self.sections if s.section_type == section_type]

    def get_interfaces(self) -> list[ParsedSection]:
        return self.get_sections("interface")

    def get_acls(self) -> list[ParsedSection]:
        return self.get_sections("acl")

    def get_vlans(self) -> list[ParsedSection]:
        return self.get_sections("vlan")


class BaseParser(ABC):
    """Abstract base class for vendor-specific config parsers."""

    @abstractmethod
    def parse(self, config_text: str) -> ParsedConfig:
        """Parse raw config text into a structured representation."""
        ...

    @abstractmethod
    def supports(self, vendor: str, os_version: str | None = None) -> bool:
        """Check if this parser supports the given vendor/OS."""
        ...
