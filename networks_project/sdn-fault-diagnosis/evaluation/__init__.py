"""
Evaluation module for SDN fault diagnosis.

This module provides:
- runner: Experiment orchestration
- metrics: Performance metric computation
- stats: Statistical tests for comparison
"""

from .metrics import (
    ClassificationMetrics,
    EngineMetrics,
    LocalizationMetrics,
    MetricsComputer,
    TimeMetrics,
)
from .stats import (
    StatisticalTestResult,
    bootstrap_accuracy_ci,
    bootstrap_accuracy_difference_ci,
    mcnemar_test,
    run_all_tests,
    wilcoxon_signed_rank_test,
)
from .runner import ExperimentRunner

__all__ = [
    # Metrics
    "ClassificationMetrics",
    "EngineMetrics",
    "LocalizationMetrics",
    "MetricsComputer",
    "TimeMetrics",
    # Stats
    "StatisticalTestResult",
    "bootstrap_accuracy_ci",
    "bootstrap_accuracy_difference_ci",
    "mcnemar_test",
    "run_all_tests",
    "wilcoxon_signed_rank_test",
    # Runner
    "ExperimentRunner",
]
