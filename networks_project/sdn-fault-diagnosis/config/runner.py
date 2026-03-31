"""
CLI runner for the config-fix pipeline.

Workflow:
1) Load config and intent
2) Validate; if clean, exit
3) If planner enabled, generate patched config
4) Re-validate patched config and report conformance
"""

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .intent import Intent
from .planner import ConfigPlan, LLMConfigPlanner, MockConfigPlanner
from .validator import ValidationError, ValidationReport, validate_config


@dataclass
class RunResult:
    initial_report: ValidationReport
    patched_report: Optional[ValidationReport] = None
    plan: Optional[ConfigPlan] = None
    patched_path: Optional[Path] = None

    @property
    def improved(self) -> bool:
        if not self.plan or not self.patched_report:
            return False
        return len(self.initial_report.errors) > 0 and self.patched_report.passed


def _load_config(path: Path) -> str:
    return path.read_text()


def _save_config(text: str, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def run_pipeline(
    config_path: Path,
    intent_path: Path,
    planner_type: str = "mock",
    fixed_config_path: Optional[Path] = None,
    output_path: Optional[Path] = None,
) -> RunResult:
    config_text = _load_config(config_path)
    intent = Intent.from_file(intent_path)

    initial_report = validate_config(config_text, intent)
    if initial_report.passed:
        return RunResult(initial_report=initial_report)

    if planner_type == "none":
        return RunResult(initial_report=initial_report)
    if planner_type == "mock":
        if not fixed_config_path:
            raise ValueError("fixed_config_path required for mock planner")
        planner = MockConfigPlanner(fixed_config_path)
    elif planner_type == "llm":
        planner = LLMConfigPlanner()
    else:
        raise ValueError(f"Unknown planner_type: {planner_type}")

    plan = planner.plan(config_text, intent, initial_report.errors)
    patched_path = output_path or (config_path.parent / f"{config_path.stem}.patched.conf")
    _save_config(plan.patched_config, patched_path)

    patched_report = validate_config(plan.patched_config, intent)

    return RunResult(
        initial_report=initial_report,
        patched_report=patched_report,
        plan=plan,
        patched_path=patched_path,
    )


def _print_report(label: str, report: ValidationReport):
    status = "OK" if report.passed else "FAILED"
    print(f"{label}: {status}")
    for err in report.errors:
        ctx = json.dumps(err.context) if err.context else ""
        print(f"  - {err.code}: {err.message} {ctx}")


def main(argv: Optional[List[str]] = None):
    parser = argparse.ArgumentParser(description="LLM-assisted config fix runner")
    parser.add_argument("--config", required=True, type=Path, help="Path to config file")
    parser.add_argument("--intent", required=True, type=Path, help="Path to intent file (json/yaml)")
    parser.add_argument("--planner", choices=["mock", "llm", "none"], default="mock", help="Planner to use")
    parser.add_argument("--fixed", type=Path, help="Fixed config path (mock planner)")
    parser.add_argument("--output", type=Path, help="Where to write patched config")

    args = parser.parse_args(argv)

    result = run_pipeline(
        config_path=args.config,
        intent_path=args.intent,
        planner_type=args.planner,
        fixed_config_path=args.fixed,
        output_path=args.output,
    )

    _print_report("Initial validation", result.initial_report)

    if result.plan:
        print("\nPlanner reasoning:")
        print(result.plan.reasoning)

    if result.patched_report:
        _print_report("Patched validation", result.patched_report)
        if result.improved:
            print(f"\nPatched config written to: {result.patched_path}")
        else:
            print("\nPatch did not resolve all issues.")


if __name__ == "__main__":
    main(sys.argv[1:])
