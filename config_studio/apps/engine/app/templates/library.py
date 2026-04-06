"""Starter template library loader for Config Studio.

Loads curated starter templates from the engine defaults directory so the UI
can fetch them from the backend instead of duplicating template definitions.
"""

from __future__ import annotations

import json
from pathlib import Path


_DEFAULTS_DIR = Path(__file__).resolve().parent / "defaults"
_TEMPLATE_FILES = {
    "cis": _DEFAULTS_DIR / "cis_cisco_ios.json",
    "disa": _DEFAULTS_DIR / "disa_stig_junos.json",
    "pci": _DEFAULTS_DIR / "pci_dss_network.json",
}


def load_starter_templates() -> list[dict]:
    templates = []
    for key, path in _TEMPLATE_FILES.items():
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        data["key"] = key
        data.setdefault("version", "starter-v1")
        templates.append(data)
    return templates


def get_starter_template(template_key: str) -> dict | None:
    for template in load_starter_templates():
        if template.get("key") == template_key:
            return template
    return None
