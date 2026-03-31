"""
Tests for the config validation and fix pipeline.

Covers all 6 config-error scenarios:
1. ospf_area_mismatch     — wrong area ID
2. missing_network        — host subnet not advertised
3. missing_router_id      — no explicit router-id
4. duplicate_router_id    — router-id conflicts with another router
5. interface_typo         — interface name misspelled
6. missing_auth           — OSPF authentication missing
"""

from pathlib import Path

import pytest

from config.intent import Intent
from config.runner import run_pipeline
from config.scenarios import get_scenario, get_all_scenarios, SCENARIOS
from config.validator import validate_config


# ======================================================================
# Parametrized validation tests — one per scenario
# ======================================================================

@pytest.mark.parametrize("scenario_name", list(SCENARIOS.keys()))
def test_validator_detects_errors(scenario_name):
    """Validator should detect the expected error codes for each scenario."""
    scenario = get_scenario(scenario_name)
    assert scenario, f"Scenario {scenario_name} not found"

    config_text = scenario.broken_config.read_text()
    intent = Intent.from_file(scenario.intent)

    report = validate_config(config_text, intent)
    codes = {err.code for err in report.errors}

    assert not report.passed, f"{scenario_name}: broken config should fail validation"
    for expected_code in scenario.expected_error_codes:
        assert expected_code in codes, (
            f"{scenario_name}: expected {expected_code}, got {codes}"
        )


@pytest.mark.parametrize("scenario_name", list(SCENARIOS.keys()))
def test_fixed_config_passes_validation(scenario_name):
    """The fixed config should pass validation cleanly."""
    scenario = get_scenario(scenario_name)
    assert scenario, f"Scenario {scenario_name} not found"

    config_text = scenario.fixed_config.read_text()
    intent = Intent.from_file(scenario.intent)

    report = validate_config(config_text, intent)
    assert report.passed, (
        f"{scenario_name}: fixed config should pass, but got errors: "
        f"{[e.code for e in report.errors]}"
    )


# ======================================================================
# Pipeline tests — mock planner resolves each scenario
# ======================================================================

@pytest.mark.parametrize("scenario_name", list(SCENARIOS.keys()))
def test_pipeline_mock_planner_resolves(scenario_name, tmp_path: Path):
    """Mock planner should produce a patched config that passes validation."""
    scenario = get_scenario(scenario_name)
    assert scenario, f"Scenario {scenario_name} not found"

    patched_path = tmp_path / f"{scenario_name}_patched.conf"
    result = run_pipeline(
        config_path=scenario.broken_config,
        intent_path=scenario.intent,
        planner_type="mock",
        fixed_config_path=scenario.fixed_config,
        output_path=patched_path,
    )

    assert result.initial_report.errors, f"{scenario_name}: should have initial errors"
    assert result.patched_report is not None
    assert result.patched_report.passed, (
        f"{scenario_name}: patched config should pass, but got: "
        f"{[e.code for e in result.patched_report.errors]}"
    )
    assert result.improved


# ======================================================================
# Scenario registry tests
# ======================================================================

def test_all_scenarios_count():
    """Should have 6 scenarios registered."""
    assert len(SCENARIOS) == 6


def test_get_all_scenarios():
    scenarios = get_all_scenarios()
    assert len(scenarios) == 6
    names = {s.name for s in scenarios}
    assert "ospf_area_mismatch" in names
    assert "missing_network" in names
    assert "missing_router_id" in names
    assert "duplicate_router_id" in names
    assert "interface_typo" in names
    assert "missing_auth" in names


def test_scenario_fixture_files_exist():
    """All fixture files should exist on disk."""
    for name, scenario in SCENARIOS.items():
        assert scenario.broken_config.exists(), f"{name}: broken.conf missing"
        assert scenario.fixed_config.exists(), f"{name}: fixed.conf missing"
        assert scenario.intent.exists(), f"{name}: intent.json missing"


def test_get_nonexistent_scenario():
    assert get_scenario("nonexistent") is None
