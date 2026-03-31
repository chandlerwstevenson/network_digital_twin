"""
Unit tests for statistical analysis and cost metrics.

Tests cover:
- Bootstrap CIs for all 4 engines
- McNemar's test for any engine pair
- Cohen's h effect size computation
- Cost metrics (LLM, hybrid, free engines)
- run_all_tests with all engines present
- Edge cases (identical engines, no trials)
"""

import json
import math

import numpy as np
import pytest

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from telemetry.schemas import DiagnosisResult, TrialResult
from evaluation.stats import (
    bootstrap_accuracy_ci,
    bootstrap_accuracy_difference_ci,
    cohens_h,
    cohens_h_interpretation,
    compute_cost_metrics,
    mcnemar_test,
    run_all_tests,
    wilcoxon_signed_rank_test,
)


def _make_trial(
    gt_class: str = "link_failure",
    rb_class: str = "link_failure",
    llm_class: str = "link_failure",
    ml_class: str = None,
    hybrid_class: str = None,
    rb_time: int = 5,
    llm_time: int = 2000,
    llm_input_tokens: int = 5000,
    llm_output_tokens: int = 400,
    hybrid_source: str = "rule_based",
) -> TrialResult:
    """Build a minimal TrialResult for testing."""
    llm_artifact = json.dumps({
        "response": {"fault_class": llm_class},
        "artifact": {
            "input_tokens": llm_input_tokens,
            "output_tokens": llm_output_tokens,
        },
    })

    hybrid_raw = json.dumps({"source": hybrid_source})

    ml_diag = None
    if ml_class is not None:
        ml_diag = DiagnosisResult(
            fault_detected=ml_class != "none",
            fault_class=ml_class if ml_class != "none" else None,
            confidence=0.9,
            diagnosis_time_ms=2,
        )

    hybrid_diag = None
    if hybrid_class is not None:
        hybrid_diag = DiagnosisResult(
            fault_detected=hybrid_class != "none",
            fault_class=hybrid_class if hybrid_class != "none" else None,
            confidence=0.9,
            diagnosis_time_ms=rb_time if hybrid_source == "rule_based" else llm_time,
            raw_output=hybrid_raw,
        )

    return TrialResult(
        trial_id="t1",
        injected_fault_type=gt_class,
        injected_fault_location="spine1:eth1",
        pre_fault_snapshot_id="pre",
        post_fault_snapshot_id="post",
        rule_based_diagnosis=DiagnosisResult(
            fault_detected=True,
            fault_class=rb_class,
            confidence=0.9,
            diagnosis_time_ms=rb_time,
        ),
        llm_diagnosis=DiagnosisResult(
            fault_detected=True,
            fault_class=llm_class,
            confidence=0.9,
            diagnosis_time_ms=llm_time,
            raw_output=llm_artifact,
        ),
        ml_diagnosis=ml_diag,
        hybrid_diagnosis=hybrid_diag,
    )


class TestBootstrapCI:
    def test_perfect_accuracy_ci(self):
        """100% accuracy should have tight CI near 1.0."""
        trials = [_make_trial() for _ in range(50)]
        lo, hi = bootstrap_accuracy_ci(trials, "rule_based")
        assert lo >= 0.9
        assert hi == 1.0

    def test_mixed_accuracy_ci(self):
        """Mixed results should have wider CI."""
        trials = []
        for i in range(50):
            rb = "link_failure" if i % 2 == 0 else "stale_route"
            trials.append(_make_trial(rb_class=rb))
        lo, hi = bootstrap_accuracy_ci(trials, "rule_based")
        assert lo < 0.6
        assert hi > 0.4

    def test_ci_for_ml_engine(self):
        trials = [_make_trial(ml_class="link_failure") for _ in range(30)]
        lo, hi = bootstrap_accuracy_ci(trials, "ml")
        assert lo >= 0.85

    def test_ci_for_hybrid_engine(self):
        trials = [_make_trial(hybrid_class="link_failure") for _ in range(30)]
        lo, hi = bootstrap_accuracy_ci(trials, "hybrid")
        assert lo >= 0.85

    def test_difference_ci_same_engines(self):
        """When both engines are identical, difference CI should span 0."""
        trials = [_make_trial() for _ in range(50)]
        lo, hi = bootstrap_accuracy_difference_ci(trials, "rule_based", "llm")
        assert lo <= 0.0 <= hi


class TestMcNemar:
    def test_identical_engines(self):
        """Identical engines should show no significant difference."""
        trials = [_make_trial() for _ in range(50)]
        result = mcnemar_test(trials, "rule_based", "llm")
        assert result.significant is False
        assert result.p_value == 1.0

    def test_one_engine_better(self):
        """When one engine always wins discordant pairs, should be significant."""
        trials = []
        for _ in range(30):
            # LLM correct, rule-based wrong
            trials.append(_make_trial(rb_class="stale_route", llm_class="link_failure"))
        for _ in range(5):
            # Both correct
            trials.append(_make_trial())
        result = mcnemar_test(trials, "rule_based", "llm")
        assert result.significant is True

    def test_mcnemar_any_pair(self):
        """McNemar should work for any engine pair."""
        trials = [_make_trial(ml_class="link_failure", hybrid_class="link_failure") for _ in range(20)]
        result = mcnemar_test(trials, "ml", "hybrid")
        assert result.test_name == "McNemar (ml vs hybrid)"


class TestCohensH:
    def test_identical_proportions(self):
        assert cohens_h(0.8, 0.8) == pytest.approx(0.0)

    def test_large_effect(self):
        h = cohens_h(0.95, 0.50)
        assert abs(h) > 0.8
        assert cohens_h_interpretation(h) == "large"

    def test_small_effect(self):
        h = cohens_h(0.82, 0.78)
        assert abs(h) < 0.2
        assert cohens_h_interpretation(h) == "negligible"

    def test_medium_effect(self):
        h = cohens_h(0.90, 0.65)
        interp = cohens_h_interpretation(h)
        assert interp in ("small", "medium", "medium")


class TestCostMetrics:
    def test_free_engines_zero_cost(self):
        trials = [_make_trial(ml_class="link_failure") for _ in range(10)]
        costs = compute_cost_metrics(trials, ["rule_based", "ml"])
        assert costs["rule_based"]["total_cost_usd"] == 0.0
        assert costs["ml"]["total_cost_usd"] == 0.0

    def test_llm_has_cost(self):
        trials = [_make_trial(llm_input_tokens=5000, llm_output_tokens=400) for _ in range(10)]
        costs = compute_cost_metrics(trials, ["llm"])
        assert costs["llm"]["total_cost_usd"] > 0.0
        assert costs["llm"]["cost_per_diagnosis_usd"] > 0.0

    def test_hybrid_cheaper_than_llm(self):
        """Hybrid with mostly rule-based accepted should cost less than always-LLM."""
        trials = []
        for _ in range(8):
            # Hybrid accepted by rule-based (free)
            trials.append(_make_trial(
                hybrid_class="link_failure", hybrid_source="rule_based",
                llm_input_tokens=5000, llm_output_tokens=400,
            ))
        for _ in range(2):
            # Hybrid deferred to LLM (costs money)
            trials.append(_make_trial(
                hybrid_class="link_failure", hybrid_source="llm_deferred",
                llm_input_tokens=5000, llm_output_tokens=400,
            ))

        costs = compute_cost_metrics(trials, ["llm", "hybrid"])
        assert costs["hybrid"]["total_cost_usd"] < costs["llm"]["total_cost_usd"]

    def test_cost_per_correct(self):
        """When some diagnoses are wrong, cost_per_correct > cost_per_diagnosis."""
        trials = []
        for _ in range(5):
            trials.append(_make_trial(llm_class="link_failure"))  # correct
        for _ in range(5):
            trials.append(_make_trial(llm_class="stale_route"))  # wrong
        costs = compute_cost_metrics(trials, ["llm"])
        assert costs["llm"]["cost_per_correct_usd"] > costs["llm"]["cost_per_diagnosis_usd"]


class TestRunAllTests:
    def test_basic_run(self):
        trials = [_make_trial() for _ in range(20)]
        result = run_all_tests(trials)
        assert "summary" in result
        assert "bootstrap_ci" in result
        assert "pairwise_comparisons" in result
        assert "cost_analysis" in result
        assert result["summary"]["n_trials"] == 20

    def test_all_engines(self):
        trials = [_make_trial(ml_class="link_failure", hybrid_class="link_failure") for _ in range(20)]
        result = run_all_tests(trials)
        assert set(result["summary"]["engines_compared"]) == {"rule_based", "llm", "ml", "hybrid"}
        # Should have C(4,2) = 6 pairwise comparisons
        assert len(result["pairwise_comparisons"]) == 6

    def test_legacy_fields_present(self):
        """Backward-compatible fields should still exist."""
        trials = [_make_trial() for _ in range(10)]
        result = run_all_tests(trials)
        assert "mcnemar_classification" in result
        assert "wilcoxon_time" in result

    def test_empty_trials(self):
        result = run_all_tests([])
        assert "error" in result

    def test_cohens_h_in_pairwise(self):
        trials = [_make_trial() for _ in range(20)]
        result = run_all_tests(trials)
        for key, comparison in result["pairwise_comparisons"].items():
            assert "cohens_h" in comparison
            assert "cohens_h_interpretation" in comparison
            assert "accuracy_difference_ci_95" in comparison
