"""
Fault injection module for SDN fault diagnosis.

This module provides:
- fault_types: Definitions of injectable faults
- injector: Fault injection harness
- scenarios: Pre-defined fault scenarios
"""

from .fault_types import (
    BaseFault,
    CounterAnomaly,
    FaultClass,
    FaultResult,
    FlappingLink,
    LinkFailure,
    MissingRoute,
    StaleRoute,
    create_fault,
)
from .injector import FaultInjector, FaultRecord
from .scenarios import (
    ALL_SCENARIOS,
    COMPOUND_FAULT_SCENARIOS,
    FaultSpec,
    Scenario,
    ScenarioType,
    SINGLE_FAULT_SCENARIOS,
    generate_random_scenario,
    get_balanced_scenario_set,
    get_scenarios_by_fault_class,
    get_scenarios_by_type,
)

__all__ = [
    # Fault types
    "BaseFault",
    "CounterAnomaly",
    "FaultClass",
    "FaultResult",
    "FlappingLink",
    "LinkFailure",
    "MissingRoute",
    "StaleRoute",
    "create_fault",
    # Injector
    "FaultInjector",
    "FaultRecord",
    # Scenarios
    "ALL_SCENARIOS",
    "COMPOUND_FAULT_SCENARIOS",
    "FaultSpec",
    "Scenario",
    "ScenarioType",
    "SINGLE_FAULT_SCENARIOS",
    "generate_random_scenario",
    "get_balanced_scenario_set",
    "get_scenarios_by_fault_class",
    "get_scenarios_by_type",
]
