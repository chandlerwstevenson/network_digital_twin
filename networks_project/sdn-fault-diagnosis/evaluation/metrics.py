"""
Evaluation metrics for fault diagnosis comparison.

Computes:
- Classification accuracy (correct fault class)
- Localization accuracy (correct affected component)
- Time-to-diagnosis metrics
- Per-fault-class performance
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Optional

import numpy as np

import sys
sys.path.insert(0, str(__file__).rsplit('/', 2)[0])

from telemetry.schemas import DiagnosisResult, TrialResult

logger = logging.getLogger(__name__)


@dataclass
class ClassificationMetrics:
    """Metrics for classification performance."""
    total: int = 0
    correct: int = 0
    incorrect: int = 0

    # Per-class breakdown
    true_positives: dict[str, int] = field(default_factory=dict)
    false_positives: dict[str, int] = field(default_factory=dict)
    false_negatives: dict[str, int] = field(default_factory=dict)
    true_negatives: dict[str, int] = field(default_factory=dict)

    @property
    def accuracy(self) -> float:
        """Overall accuracy."""
        return self.correct / self.total if self.total > 0 else 0.0

    def precision(self, fault_class: str) -> float:
        """Precision for a specific fault class."""
        tp = self.true_positives.get(fault_class, 0)
        fp = self.false_positives.get(fault_class, 0)
        return tp / (tp + fp) if (tp + fp) > 0 else 0.0

    def recall(self, fault_class: str) -> float:
        """Recall for a specific fault class."""
        tp = self.true_positives.get(fault_class, 0)
        fn = self.false_negatives.get(fault_class, 0)
        return tp / (tp + fn) if (tp + fn) > 0 else 0.0

    def f1_score(self, fault_class: str) -> float:
        """F1 score for a specific fault class."""
        p = self.precision(fault_class)
        r = self.recall(fault_class)
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "total": self.total,
            "correct": self.correct,
            "incorrect": self.incorrect,
            "accuracy": self.accuracy,
            "true_positives": dict(self.true_positives),
            "false_positives": dict(self.false_positives),
            "false_negatives": dict(self.false_negatives),
        }


@dataclass
class LocalizationMetrics:
    """Metrics for fault localization performance."""
    total: int = 0
    correct: int = 0
    partial: int = 0  # Correct router but wrong interface
    incorrect: int = 0

    @property
    def accuracy(self) -> float:
        """Exact localization accuracy."""
        return self.correct / self.total if self.total > 0 else 0.0

    @property
    def partial_accuracy(self) -> float:
        """Accuracy including partial matches."""
        return (self.correct + self.partial) / self.total if self.total > 0 else 0.0

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "total": self.total,
            "correct": self.correct,
            "partial": self.partial,
            "incorrect": self.incorrect,
            "accuracy": self.accuracy,
            "partial_accuracy": self.partial_accuracy,
        }


@dataclass
class TimeMetrics:
    """Metrics for diagnosis time."""
    times_ms: list[int] = field(default_factory=list)

    @property
    def mean(self) -> float:
        """Mean diagnosis time in ms."""
        return np.mean(self.times_ms) if self.times_ms else 0.0

    @property
    def std(self) -> float:
        """Standard deviation of diagnosis time."""
        return np.std(self.times_ms) if self.times_ms else 0.0

    @property
    def median(self) -> float:
        """Median diagnosis time."""
        return np.median(self.times_ms) if self.times_ms else 0.0

    @property
    def p95(self) -> float:
        """95th percentile diagnosis time."""
        return np.percentile(self.times_ms, 95) if self.times_ms else 0.0

    @property
    def p99(self) -> float:
        """99th percentile diagnosis time."""
        return np.percentile(self.times_ms, 99) if self.times_ms else 0.0

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "count": len(self.times_ms),
            "mean_ms": self.mean,
            "std_ms": self.std,
            "median_ms": self.median,
            "p95_ms": self.p95,
            "p99_ms": self.p99,
            "min_ms": min(self.times_ms) if self.times_ms else 0,
            "max_ms": max(self.times_ms) if self.times_ms else 0,
        }


@dataclass
class EngineMetrics:
    """Complete metrics for a diagnostic engine."""
    name: str
    classification: ClassificationMetrics = field(default_factory=ClassificationMetrics)
    localization: LocalizationMetrics = field(default_factory=LocalizationMetrics)
    time: TimeMetrics = field(default_factory=TimeMetrics)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "classification": self.classification.to_dict(),
            "localization": self.localization.to_dict(),
            "time": self.time.to_dict(),
        }


class MetricsComputer:
    """
    Computes evaluation metrics from trial results.

    Tracks metrics for both rule-based and LLM engines
    and provides comparison utilities.
    """

    def __init__(self):
        """Initialize metrics computer."""
        self.rule_based = EngineMetrics(name="rule-based")
        self.llm = EngineMetrics(name="llm-agent")
        self.ml = EngineMetrics(name="ml-random-forest")
        self.hybrid = EngineMetrics(name="hybrid")
        self.trials: list[TrialResult] = []

    def add_trial(self, trial: TrialResult):
        """
        Add a trial result and update metrics.

        Args:
            trial: Completed trial result
        """
        self.trials.append(trial)

        # Update rule-based metrics
        self._update_classification(
            self.rule_based.classification,
            trial.injected_fault_type,
            trial.rule_based_diagnosis.fault_class,
        )
        self._update_localization(
            self.rule_based.localization,
            trial.injected_fault_location,
            trial.rule_based_diagnosis.location,
        )
        self.rule_based.time.times_ms.append(
            trial.rule_based_diagnosis.diagnosis_time_ms
        )

        # Update LLM metrics
        self._update_classification(
            self.llm.classification,
            trial.injected_fault_type,
            trial.llm_diagnosis.fault_class,
        )
        self._update_localization(
            self.llm.localization,
            trial.injected_fault_location,
            trial.llm_diagnosis.location,
        )
        self.llm.time.times_ms.append(
            trial.llm_diagnosis.diagnosis_time_ms
        )

        # Update hybrid metrics (if present)
        if trial.hybrid_diagnosis is not None:
            self._update_classification(
                self.hybrid.classification,
                trial.injected_fault_type,
                trial.hybrid_diagnosis.fault_class,
            )
            self._update_localization(
                self.hybrid.localization,
                trial.injected_fault_location,
                trial.hybrid_diagnosis.location,
            )
            self.hybrid.time.times_ms.append(
                trial.hybrid_diagnosis.diagnosis_time_ms
            )

        # Update ML metrics (if ML diagnosis is present)
        if trial.ml_diagnosis is not None:
            self._update_classification(
                self.ml.classification,
                trial.injected_fault_type,
                trial.ml_diagnosis.fault_class,
            )
            self._update_localization(
                self.ml.localization,
                trial.injected_fault_location,
                trial.ml_diagnosis.location,
            )
            self.ml.time.times_ms.append(
                trial.ml_diagnosis.diagnosis_time_ms
            )

    def _update_classification(
        self,
        metrics: ClassificationMetrics,
        ground_truth: str,
        predicted: Optional[str]
    ):
        """Update classification metrics for a single prediction."""
        metrics.total += 1

        if predicted == ground_truth:
            metrics.correct += 1
            # True positive for this class
            if ground_truth not in metrics.true_positives:
                metrics.true_positives[ground_truth] = 0
            metrics.true_positives[ground_truth] += 1
        else:
            metrics.incorrect += 1
            # False negative for ground truth class
            if ground_truth not in metrics.false_negatives:
                metrics.false_negatives[ground_truth] = 0
            metrics.false_negatives[ground_truth] += 1
            # False positive for predicted class (if any)
            if predicted:
                if predicted not in metrics.false_positives:
                    metrics.false_positives[predicted] = 0
                metrics.false_positives[predicted] += 1

    def _update_localization(
        self,
        metrics: LocalizationMetrics,
        ground_truth: str,
        predicted: Optional[str]
    ):
        """Update localization metrics for a single prediction."""
        metrics.total += 1

        if not predicted:
            metrics.incorrect += 1
            return

        if predicted == ground_truth:
            metrics.correct += 1
        elif self._partial_match(ground_truth, predicted):
            metrics.partial += 1
        else:
            metrics.incorrect += 1

    def _partial_match(self, ground_truth: str, predicted: str) -> bool:
        """
        Check for partial location match.

        Returns True if the router matches but interface/prefix differs.
        """
        if ":" not in ground_truth or ":" not in predicted:
            return False

        gt_router = ground_truth.split(":")[0]
        pred_router = predicted.split(":")[0]

        return gt_router == pred_router

    def get_comparison(self) -> dict:
        """
        Get comparison between all engines.

        Returns:
            Dict with comparative metrics
        """
        result = {
            "trial_count": len(self.trials),
            "rule_based": self.rule_based.to_dict(),
            "llm_agent": self.llm.to_dict(),
            "comparison": {
                "classification_accuracy_diff": (
                    self.llm.classification.accuracy -
                    self.rule_based.classification.accuracy
                ),
                "localization_accuracy_diff": (
                    self.llm.localization.accuracy -
                    self.rule_based.localization.accuracy
                ),
                "mean_time_diff_ms": (
                    self.llm.time.mean -
                    self.rule_based.time.mean
                ),
            }
        }

        # Include hybrid engine if it has data
        if self.hybrid.classification.total > 0:
            result["hybrid_engine"] = self.hybrid.to_dict()
            result["comparison"]["hybrid_vs_rule_based_accuracy_diff"] = (
                self.hybrid.classification.accuracy -
                self.rule_based.classification.accuracy
            )
            result["comparison"]["hybrid_vs_llm_accuracy_diff"] = (
                self.hybrid.classification.accuracy -
                self.llm.classification.accuracy
            )
            result["comparison"]["hybrid_mean_time_ms"] = self.hybrid.time.mean

        # Include ML engine if it has data
        if self.ml.classification.total > 0:
            result["ml_engine"] = self.ml.to_dict()
            result["comparison"]["ml_vs_rule_based_accuracy_diff"] = (
                self.ml.classification.accuracy -
                self.rule_based.classification.accuracy
            )
            result["comparison"]["ml_vs_llm_accuracy_diff"] = (
                self.ml.classification.accuracy -
                self.llm.classification.accuracy
            )

        return result

    def get_per_class_metrics(self) -> dict:
        """Get metrics broken down by fault class."""
        fault_classes = set()
        for trial in self.trials:
            fault_classes.add(trial.injected_fault_type)

        per_class = {}
        for fc in fault_classes:
            fc_trials = [t for t in self.trials if t.injected_fault_type == fc]
            entry = {
                "count": len(fc_trials),
                "rule_based": {
                    "correct": sum(
                        1 for t in fc_trials
                        if t.rule_based_diagnosis.fault_class == fc
                    ),
                    "precision": self.rule_based.classification.precision(fc),
                    "recall": self.rule_based.classification.recall(fc),
                    "f1": self.rule_based.classification.f1_score(fc),
                },
                "llm": {
                    "correct": sum(
                        1 for t in fc_trials
                        if t.llm_diagnosis.fault_class == fc
                    ),
                    "precision": self.llm.classification.precision(fc),
                    "recall": self.llm.classification.recall(fc),
                    "f1": self.llm.classification.f1_score(fc),
                }
            }

            if self.hybrid.classification.total > 0:
                entry["hybrid"] = {
                    "correct": sum(
                        1 for t in fc_trials
                        if t.hybrid_diagnosis and t.hybrid_diagnosis.fault_class == fc
                    ),
                    "precision": self.hybrid.classification.precision(fc),
                    "recall": self.hybrid.classification.recall(fc),
                    "f1": self.hybrid.classification.f1_score(fc),
                }

            if self.ml.classification.total > 0:
                entry["ml"] = {
                    "correct": sum(
                        1 for t in fc_trials
                        if t.ml_diagnosis and t.ml_diagnosis.fault_class == fc
                    ),
                    "precision": self.ml.classification.precision(fc),
                    "recall": self.ml.classification.recall(fc),
                    "f1": self.ml.classification.f1_score(fc),
                }

            per_class[fc] = entry

        return per_class

    def get_confusion_matrix(self, engine: str = "llm") -> dict:
        """
        Get confusion matrix for an engine.

        Args:
            engine: "rule_based", "llm", or "ml"

        Returns:
            Dict with actual -> predicted -> count
        """
        matrix: dict[str, dict[str, int]] = {}

        for trial in self.trials:
            actual = trial.injected_fault_type
            if engine == "llm":
                predicted = trial.llm_diagnosis.fault_class or "none"
            elif engine == "hybrid":
                if trial.hybrid_diagnosis is None:
                    continue
                predicted = trial.hybrid_diagnosis.fault_class or "none"
            elif engine == "ml":
                if trial.ml_diagnosis is None:
                    continue
                predicted = trial.ml_diagnosis.fault_class or "none"
            else:
                predicted = trial.rule_based_diagnosis.fault_class or "none"

            if actual not in matrix:
                matrix[actual] = {}
            if predicted not in matrix[actual]:
                matrix[actual][predicted] = 0
            matrix[actual][predicted] += 1

        return matrix

    def reset(self):
        """Reset all metrics."""
        self.rule_based = EngineMetrics(name="rule-based")
        self.llm = EngineMetrics(name="llm-agent")
        self.ml = EngineMetrics(name="ml-random-forest")
        self.hybrid = EngineMetrics(name="hybrid")
        self.trials.clear()
