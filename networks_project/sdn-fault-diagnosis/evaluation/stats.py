"""
Statistical tests and cost analysis for comparing diagnostic engines.

Implements:
- McNemar's test for pairwise accuracy comparison (any two engines)
- Wilcoxon signed-rank test for time comparison
- Bootstrap confidence intervals for all engines
- Cohen's h effect size for accuracy differences
- Cost-per-diagnosis and cost-per-correct-diagnosis metrics
- Full 4-engine comparison (rule-based, LLM, ML, hybrid)
"""

import json
import logging
import math
from dataclasses import dataclass
from typing import Optional

import numpy as np
from scipy import stats

import sys
sys.path.insert(0, str(__file__).rsplit('/', 2)[0])

from telemetry.schemas import TrialResult

logger = logging.getLogger(__name__)

# Default Anthropic pricing (USD per million tokens)
DEFAULT_INPUT_COST_PER_M = 3.00   # Sonnet input
DEFAULT_OUTPUT_COST_PER_M = 15.00  # Sonnet output


@dataclass
class StatisticalTestResult:
    """Result of a statistical test."""
    test_name: str
    statistic: float
    p_value: float
    significant: bool  # At alpha=0.05
    effect_size: Optional[float] = None
    confidence_interval: Optional[tuple[float, float]] = None
    interpretation: str = ""

    def to_dict(self) -> dict:
        return {
            "test_name": self.test_name,
            "statistic": self.statistic,
            "p_value": self.p_value,
            "significant": self.significant,
            "effect_size": self.effect_size,
            "confidence_interval": self.confidence_interval,
            "interpretation": self.interpretation,
        }


# ======================================================================
# Helper: extract correctness array for any engine
# ======================================================================

def _engine_correct(trials: list[TrialResult], engine: str) -> np.ndarray:
    """Return binary array: 1 = engine got it right, 0 = wrong."""
    results = []
    for t in trials:
        gt = t.injected_fault_type
        if engine == "rule_based":
            results.append(1 if t.rule_based_diagnosis.fault_class == gt else 0)
        elif engine == "llm":
            results.append(1 if t.llm_diagnosis.fault_class == gt else 0)
        elif engine == "ml":
            results.append(1 if (t.ml_diagnosis and t.ml_diagnosis.fault_class == gt) else 0)
        elif engine == "hybrid":
            results.append(1 if (t.hybrid_diagnosis and t.hybrid_diagnosis.fault_class == gt) else 0)
        else:
            results.append(0)
    return np.array(results)


def _engine_times(trials: list[TrialResult], engine: str) -> np.ndarray:
    """Return diagnosis times (ms) for an engine."""
    times = []
    for t in trials:
        if engine == "rule_based":
            times.append(t.rule_based_diagnosis.diagnosis_time_ms)
        elif engine == "llm":
            times.append(t.llm_diagnosis.diagnosis_time_ms)
        elif engine == "ml":
            times.append(t.ml_diagnosis.diagnosis_time_ms if t.ml_diagnosis else 0)
        elif engine == "hybrid":
            times.append(t.hybrid_diagnosis.diagnosis_time_ms if t.hybrid_diagnosis else 0)
    return np.array(times)


def _engine_available(trials: list[TrialResult], engine: str) -> bool:
    """Check if an engine has data in the trials."""
    if engine in ("rule_based", "llm"):
        return len(trials) > 0
    if engine == "ml":
        return any(t.ml_diagnosis is not None for t in trials)
    if engine == "hybrid":
        return any(t.hybrid_diagnosis is not None for t in trials)
    return False


# ======================================================================
# McNemar's test (generalized for any engine pair)
# ======================================================================

def mcnemar_test(
    trials: list[TrialResult],
    engine_a: str = "rule_based",
    engine_b: str = "llm",
    alpha: float = 0.05,
) -> StatisticalTestResult:
    """McNemar's test comparing two engines' classification accuracy."""
    a_correct = _engine_correct(trials, engine_a)
    b_correct = _engine_correct(trials, engine_b)

    # b wins, a loses
    b_wins = int(np.sum((b_correct == 1) & (a_correct == 0)))
    # a wins, b loses
    a_wins = int(np.sum((a_correct == 1) & (b_correct == 0)))

    if b_wins + a_wins == 0:
        return StatisticalTestResult(
            test_name=f"McNemar ({engine_a} vs {engine_b})",
            statistic=0.0, p_value=1.0, significant=False,
            interpretation="No discordant pairs — engines have identical accuracy",
        )

    chi2 = (abs(b_wins - a_wins) - 1) ** 2 / (b_wins + a_wins)
    p_value = float(1 - stats.chi2.cdf(chi2, df=1))
    odds = b_wins / a_wins if a_wins > 0 else float('inf')

    if p_value < alpha:
        winner = engine_b if b_wins > a_wins else engine_a
        interp = f"{winner} significantly better (p={p_value:.4f}, discordant: {b_wins}/{a_wins})"
    else:
        interp = f"No significant difference (p={p_value:.4f}, discordant: {b_wins}/{a_wins})"

    return StatisticalTestResult(
        test_name=f"McNemar ({engine_a} vs {engine_b})",
        statistic=chi2, p_value=p_value,
        significant=p_value < alpha, effect_size=odds,
        interpretation=interp,
    )


# ======================================================================
# Wilcoxon signed-rank test
# ======================================================================

def wilcoxon_signed_rank_test(
    trials: list[TrialResult],
    engine_a: str = "rule_based",
    engine_b: str = "llm",
    alpha: float = 0.05,
) -> StatisticalTestResult:
    """Wilcoxon signed-rank test comparing two engines' diagnosis times."""
    a_times = _engine_times(trials, engine_a)
    b_times = _engine_times(trials, engine_b)
    differences = b_times - a_times

    non_zero = differences != 0
    if not np.any(non_zero):
        return StatisticalTestResult(
            test_name=f"Wilcoxon ({engine_a} vs {engine_b})",
            statistic=0.0, p_value=1.0, significant=False,
            interpretation="No time differences",
        )

    try:
        statistic, p_value = stats.wilcoxon(b_times, a_times, alternative='two-sided')
    except ValueError as e:
        return StatisticalTestResult(
            test_name=f"Wilcoxon ({engine_a} vs {engine_b})",
            statistic=0.0, p_value=1.0, significant=False,
            interpretation=f"Test failed: {e}",
        )

    n = int(np.sum(non_zero))
    r = 1 - (2 * statistic) / (n * (n + 1)) if n > 0 else 0.0
    median_diff = float(np.median(differences))

    if p_value < alpha:
        slower = engine_b if median_diff > 0 else engine_a
        interp = f"{slower} significantly slower (median Δ={median_diff:.0f}ms, p={p_value:.4f})"
    else:
        interp = f"No significant time difference (median Δ={median_diff:.0f}ms, p={p_value:.4f})"

    return StatisticalTestResult(
        test_name=f"Wilcoxon ({engine_a} vs {engine_b})",
        statistic=float(statistic), p_value=float(p_value),
        significant=p_value < alpha, effect_size=r,
        interpretation=interp,
    )


# ======================================================================
# Cohen's h effect size
# ======================================================================

def cohens_h(p1: float, p2: float) -> float:
    """
    Cohen's h effect size for comparing two proportions.

    Interpretation:
        |h| < 0.2: small
        0.2 <= |h| < 0.5: small-medium
        0.5 <= |h| < 0.8: medium-large
        |h| >= 0.8: large
    """
    return 2 * math.asin(math.sqrt(p1)) - 2 * math.asin(math.sqrt(p2))


def cohens_h_interpretation(h: float) -> str:
    ah = abs(h)
    if ah < 0.2:
        return "negligible"
    elif ah < 0.5:
        return "small"
    elif ah < 0.8:
        return "medium"
    else:
        return "large"


# ======================================================================
# Bootstrap confidence intervals (generalized)
# ======================================================================

def bootstrap_accuracy_ci(
    trials: list[TrialResult],
    engine: str,
    n_bootstrap: int = 2000,
    confidence: float = 0.95,
) -> tuple[float, float]:
    """Bootstrap 95% CI for an engine's classification accuracy."""
    correct = _engine_correct(trials, engine)
    n = len(correct)
    if n == 0:
        return (0.0, 0.0)

    rng = np.random.default_rng(42)
    boot_accs = []
    for _ in range(n_bootstrap):
        sample = correct[rng.integers(0, n, size=n)]
        boot_accs.append(float(np.mean(sample)))

    lo = (1 - confidence) / 2 * 100
    hi = (1 + confidence) / 2 * 100
    return (float(np.percentile(boot_accs, lo)), float(np.percentile(boot_accs, hi)))


def bootstrap_accuracy_difference_ci(
    trials: list[TrialResult],
    engine_a: str = "rule_based",
    engine_b: str = "llm",
    n_bootstrap: int = 2000,
    confidence: float = 0.95,
) -> tuple[float, float]:
    """Bootstrap 95% CI for accuracy difference (engine_b − engine_a)."""
    a_correct = _engine_correct(trials, engine_a)
    b_correct = _engine_correct(trials, engine_b)
    n = len(a_correct)
    if n == 0:
        return (0.0, 0.0)

    rng = np.random.default_rng(42)
    boot_diffs = []
    for _ in range(n_bootstrap):
        idx = rng.integers(0, n, size=n)
        diff = float(np.mean(b_correct[idx]) - np.mean(a_correct[idx]))
        boot_diffs.append(diff)

    lo = (1 - confidence) / 2 * 100
    hi = (1 + confidence) / 2 * 100
    return (float(np.percentile(boot_diffs, lo)), float(np.percentile(boot_diffs, hi)))


# ======================================================================
# Cost analysis
# ======================================================================

def _extract_llm_cost(trial: TrialResult, engine: str,
                      input_cpm: float, output_cpm: float) -> float:
    """Extract cost from a single trial for an engine."""
    if engine == "rule_based" or engine == "ml":
        return 0.0

    diag = None
    if engine == "llm":
        diag = trial.llm_diagnosis
    elif engine == "hybrid":
        diag = trial.hybrid_diagnosis

    if diag is None or not diag.raw_output:
        return 0.0

    try:
        raw = json.loads(diag.raw_output)
    except (json.JSONDecodeError, TypeError):
        return 0.0

    # LLM agent stores artifact with token counts
    artifact = raw.get("artifact", {})
    if artifact:
        inp = artifact.get("input_tokens", 0)
        out = artifact.get("output_tokens", 0)
        return (inp * input_cpm / 1_000_000) + (out * output_cpm / 1_000_000)

    # Hybrid stores source — only costs when deferred to LLM
    source = raw.get("source", "")
    if source == "rule_based" or source == "rule_based_fallback":
        return 0.0
    # If deferred, we don't have exact token counts in the hybrid raw_output,
    # so estimate from the LLM diagnosis on the same trial
    if source == "llm_deferred" and trial.llm_diagnosis and trial.llm_diagnosis.raw_output:
        try:
            llm_raw = json.loads(trial.llm_diagnosis.raw_output)
            llm_art = llm_raw.get("artifact", {})
            inp = llm_art.get("input_tokens", 0)
            out = llm_art.get("output_tokens", 0)
            return (inp * input_cpm / 1_000_000) + (out * output_cpm / 1_000_000)
        except (json.JSONDecodeError, TypeError):
            pass

    return 0.0


def compute_cost_metrics(
    trials: list[TrialResult],
    engines: list[str],
    input_cost_per_m: float = DEFAULT_INPUT_COST_PER_M,
    output_cost_per_m: float = DEFAULT_OUTPUT_COST_PER_M,
) -> dict:
    """
    Compute cost metrics for each engine.

    Returns per-engine:
        - total_cost: total USD across all trials
        - cost_per_diagnosis: average USD per diagnosis
        - cost_per_correct: average USD per correct diagnosis
        - accuracy: for context
    """
    result = {}

    for engine in engines:
        correct = _engine_correct(trials, engine)
        n_correct = int(np.sum(correct))
        n_total = len(correct)
        accuracy = n_correct / n_total if n_total > 0 else 0.0

        total_cost = sum(
            _extract_llm_cost(t, engine, input_cost_per_m, output_cost_per_m)
            for t in trials
        )
        cost_per_diag = total_cost / n_total if n_total > 0 else 0.0
        cost_per_correct = total_cost / n_correct if n_correct > 0 else 0.0

        result[engine] = {
            "total_cost_usd": round(total_cost, 6),
            "cost_per_diagnosis_usd": round(cost_per_diag, 6),
            "cost_per_correct_usd": round(cost_per_correct, 6),
            "accuracy": round(accuracy, 4),
            "n_correct": n_correct,
            "n_total": n_total,
        }

    return result


# ======================================================================
# Main entry point: run all tests for all available engines
# ======================================================================

ALL_ENGINES = ["rule_based", "llm", "ml", "hybrid"]


def run_all_tests(
    trials: list[TrialResult],
    input_cost_per_m: float = DEFAULT_INPUT_COST_PER_M,
    output_cost_per_m: float = DEFAULT_OUTPUT_COST_PER_M,
) -> dict:
    """
    Run all statistical tests, bootstrap CIs, effect sizes, and cost analysis.

    Automatically detects which engines have data and runs all applicable
    pairwise comparisons.
    """
    if not trials:
        return {"error": "No trials to analyze"}

    # Detect available engines
    available = [e for e in ALL_ENGINES if _engine_available(trials, e)]

    results = {}

    # --- Per-engine bootstrap CIs ---
    cis = {}
    accuracies = {}
    for engine in available:
        ci = bootstrap_accuracy_ci(trials, engine)
        correct = _engine_correct(trials, engine)
        acc = float(np.mean(correct))
        cis[engine] = {"accuracy": acc, "ci_95": ci}
        accuracies[engine] = acc
    results["bootstrap_ci"] = cis

    # --- Pairwise McNemar tests + Cohen's h + accuracy difference CIs ---
    pairwise = {}
    for i, ea in enumerate(available):
        for eb in available[i + 1:]:
            key = f"{ea}_vs_{eb}"
            mcn = mcnemar_test(trials, ea, eb)
            h = cohens_h(accuracies[ea], accuracies[eb])
            diff_ci = bootstrap_accuracy_difference_ci(trials, ea, eb)

            pairwise[key] = {
                "mcnemar": mcn.to_dict(),
                "cohens_h": round(h, 4),
                "cohens_h_interpretation": cohens_h_interpretation(h),
                "accuracy_difference": round(accuracies[eb] - accuracies[ea], 4),
                "accuracy_difference_ci_95": diff_ci,
            }
    results["pairwise_comparisons"] = pairwise

    # --- Pairwise Wilcoxon time tests ---
    time_tests = {}
    for i, ea in enumerate(available):
        for eb in available[i + 1:]:
            key = f"{ea}_vs_{eb}"
            wil = wilcoxon_signed_rank_test(trials, ea, eb)
            time_tests[key] = wil.to_dict()
    results["time_comparisons"] = time_tests

    # --- Cost analysis ---
    results["cost_analysis"] = compute_cost_metrics(
        trials, available, input_cost_per_m, output_cost_per_m
    )

    # --- Legacy fields for backward compatibility ---
    results["mcnemar_classification"] = mcnemar_test(trials, "rule_based", "llm").to_dict()
    results["wilcoxon_time"] = wilcoxon_signed_rank_test(trials, "rule_based", "llm").to_dict()

    # --- Summary ---
    results["summary"] = {
        "n_trials": len(trials),
        "engines_compared": available,
        "accuracies": {e: round(accuracies[e], 4) for e in available},
    }

    return results
