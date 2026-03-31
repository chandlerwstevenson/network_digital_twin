"""
Intent models for FRR/OSPF configuration.

These dataclasses capture desired router state and are used to guide
validation and LLM planning.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    yaml = None


@dataclass
class NetworkIntent:
    """Desired OSPF network advertisement."""
    prefix: str
    area: str = "0"
    auth_required: bool = False


@dataclass
class InterfaceIntent:
    """Desired interface-level OSPF properties."""
    name: str
    area: Optional[str] = None
    auth_required: bool = False


@dataclass
class Intent:
    """Desired router intent used for validation and planning."""
    router_id: Optional[str] = None
    networks: List[NetworkIntent] = field(default_factory=list)
    interfaces: Dict[str, InterfaceIntent] = field(default_factory=dict)
    description: str = ""

    @staticmethod
    def _coerce_network(item: Dict[str, Any]) -> NetworkIntent:
        return NetworkIntent(
            prefix=item["prefix"],
            area=str(item.get("area", "0")),
            auth_required=bool(item.get("auth_required", False)),
        )

    @staticmethod
    def _coerce_interface(name: str, item: Dict[str, Any]) -> InterfaceIntent:
        return InterfaceIntent(
            name=name,
            area=str(item.get("area")) if item.get("area") is not None else None,
            auth_required=bool(item.get("auth_required", False)),
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Intent":
        networks = [cls._coerce_network(n) for n in data.get("networks", [])]
        interfaces = {
            name: cls._coerce_interface(name, i)
            for name, i in data.get("interfaces", {}).items()
        }
        return cls(
            router_id=data.get("router_id"),
            networks=networks,
            interfaces=interfaces,
            description=data.get("description", ""),
        )

    @classmethod
    def from_file(cls, path: Path) -> "Intent":
        """Load intent from JSON or YAML file."""
        with open(path, "r") as f:
            text = f.read()

        if path.suffix.lower() in {".yml", ".yaml"} and yaml:
            data = yaml.safe_load(text)
        else:
            data = json.loads(text)

        if not isinstance(data, dict):
            raise ValueError(f"Invalid intent file: {path}")

        return cls.from_dict(data)
