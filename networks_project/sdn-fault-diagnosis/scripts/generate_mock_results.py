#!/usr/bin/env python3
"""
Generate mock experiment results for the dashboard.

Use when you want to see the dashboard without running a full lab.

Outputs:
- evaluation/results/results_mock.json
- evaluation/results/trials_mock.json
"""

import json
from datetime import datetime
from pathlib import Path


def main():
    base = Path(__file__).resolve().parent.parent / "evaluation" / "results"
    base.mkdir(parents=True, exist_ok=True)

    now = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    results_path = base / f"results_{now}_mock.json"
    trials_path = base / f"trials_{now}_mock.json"

    metrics = {
        "trial_count": 3,
        "rule_based": {
            "name": "rule-based",
            "classification": {"total": 3, "correct": 2, "incorrect": 1, "accuracy": 0.666},
            "localization": {"total": 3, "correct": 2, "partial": 1, "incorrect": 0, "accuracy": 0.666, "partial_accuracy": 1.0},
            "time": {"count": 3, "mean_ms": 45, "std_ms": 5, "median_ms": 44, "p95_ms": 52, "p99_ms": 52, "min_ms": 40, "max_ms": 52},
        },
        "llm_agent": {
            "name": "llm-agent",
            "classification": {"total": 3, "correct": 3, "incorrect": 0, "accuracy": 1.0},
            "localization": {"total": 3, "correct": 3, "partial": 0, "incorrect": 0, "accuracy": 1.0, "partial_accuracy": 1.0},
            "time": {"count": 3, "mean_ms": 210, "std_ms": 20, "median_ms": 205, "p95_ms": 240, "p99_ms": 240, "min_ms": 190, "max_ms": 240},
        },
        "comparison": {
            "classification_accuracy_diff": 0.334,
            "localization_accuracy_diff": 0.334,
            "mean_time_diff_ms": 165,
        },
    }

    per_class = {
        "link_failure": {
            "count": 2,
            "rule_based": {"correct": 1, "precision": 0.5, "recall": 0.5, "f1": 0.5},
            "llm": {"correct": 2, "precision": 1.0, "recall": 1.0, "f1": 1.0},
        },
        "missing_route": {
            "count": 1,
            "rule_based": {"correct": 1, "precision": 1.0, "recall": 1.0, "f1": 1.0},
            "llm": {"correct": 1, "precision": 1.0, "recall": 1.0, "f1": 1.0},
        },
    }

    statistical_tests = {
        "mcnemar_classification": {
            "test_name": "McNemar's Test",
            "statistic": 1.0,
            "p_value": 0.3173,
            "significant": False,
            "interpretation": "No significant difference in accuracy",
        },
        "wilcoxon_time": {
            "test_name": "Wilcoxon Signed-Rank Test",
            "statistic": 0.0,
            "p_value": 0.1,
            "significant": False,
            "interpretation": "LLM slower but not significant in this mock",
        },
        "bootstrap_ci": {
            "llm_accuracy_95ci": [0.8, 1.0],
            "rule_based_accuracy_95ci": [0.4, 0.9],
            "accuracy_difference_95ci": [0.0, 0.5],
        },
        "summary": {
            "n_trials": 3,
            "llm_accuracy": 1.0,
            "rule_based_accuracy": 0.666,
            "accuracy_difference": 0.334,
        },
    }

    results = {
        "experiment_id": f"mock_{now}",
        "num_trials": 3,
        "elapsed_seconds": 0,
        "metrics": metrics,
        "per_class": per_class,
        "statistical_tests": statistical_tests,
        "run_metadata": {
            "experiment_id": f"mock_{now}",
            "trials_requested": 3,
            "compound_ratio": 0.0,
            "use_mock_llm": True,
            "start_time": datetime.utcnow().isoformat(),
            "llm_model": "mock-llm",
            "llm_prompt_hash": "mock",
            "llm_temperature": 0.0,
            "llm_invocations": 3,
            "llm_cost_usd": 0.0,
            "rule_based_name": "rule-based",
        },
    }

    trials = [
        {
            "trial_id": "trial_1",
            "timestamp": datetime.utcnow().isoformat(),
            "injected_fault_type": "link_failure",
            "injected_fault_location": "spine1:eth1",
            "injected_fault_params": {},
            "pre_fault_snapshot_id": "pre1",
            "post_fault_snapshot_id": "post1",
            "rule_based_diagnosis": {
                "fault_detected": True,
                "fault_class": "link_failure",
                "location": "spine1:eth1",
                "affected_routers": ["spine1", "leaf1"],
                "affected_interfaces": ["spine1:eth1"],
                "affected_prefixes": [],
                "confidence": 0.7,
                "reasoning": "Neighbor down",
                "remediation": "Bring interface up",
                "diagnosis_time_ms": 45,
            },
            "llm_diagnosis": {
                "fault_detected": True,
                "fault_class": "link_failure",
                "location": "spine1:eth1",
                "affected_routers": ["spine1", "leaf1"],
                "affected_interfaces": ["spine1:eth1"],
                "affected_prefixes": [],
                "confidence": 0.9,
                "reasoning": "LLM mock reasoning",
                "remediation": "Bring interface up",
                "diagnosis_time_ms": 200,
            },
            "rule_based_correct_class": True,
            "rule_based_correct_location": True,
            "llm_correct_class": True,
            "llm_correct_location": True,
        },
        {
            "trial_id": "trial_2",
            "timestamp": datetime.utcnow().isoformat(),
            "injected_fault_type": "missing_route",
            "injected_fault_location": "leaf2:192.168.2.0/24",
            "injected_fault_params": {},
            "pre_fault_snapshot_id": "pre2",
            "post_fault_snapshot_id": "post2",
            "rule_based_diagnosis": {
                "fault_detected": True,
                "fault_class": "missing_route",
                "location": "leaf2:192.168.2.0/24",
                "affected_routers": ["leaf2"],
                "affected_interfaces": [],
                "affected_prefixes": ["192.168.2.0/24"],
                "confidence": 0.8,
                "reasoning": "Route withdrawn",
                "remediation": "Restore network statement",
                "diagnosis_time_ms": 50,
            },
            "llm_diagnosis": {
                "fault_detected": True,
                "fault_class": "missing_route",
                "location": "leaf2:192.168.2.0/24",
                "affected_routers": ["leaf2"],
                "affected_interfaces": [],
                "affected_prefixes": ["192.168.2.0/24"],
                "confidence": 0.93,
                "reasoning": "LLM mock reasoning",
                "remediation": "Restore network statement",
                "diagnosis_time_ms": 215,
            },
            "rule_based_correct_class": True,
            "rule_based_correct_location": True,
            "llm_correct_class": True,
            "llm_correct_location": True,
        },
        {
            "trial_id": "trial_3",
            "timestamp": datetime.utcnow().isoformat(),
            "injected_fault_type": "link_failure",
            "injected_fault_location": "spine2:eth2",
            "injected_fault_params": {},
            "pre_fault_snapshot_id": "pre3",
            "post_fault_snapshot_id": "post3",
            "rule_based_diagnosis": {
                "fault_detected": True,
                "fault_class": "missing_route",
                "location": "spine2:eth2",
                "affected_routers": ["spine2", "leaf2"],
                "affected_interfaces": ["spine2:eth2"],
                "affected_prefixes": [],
                "confidence": 0.6,
                "reasoning": "False positive",
                "remediation": "Check interface",
                "diagnosis_time_ms": 40,
            },
            "llm_diagnosis": {
                "fault_detected": True,
                "fault_class": "link_failure",
                "location": "spine2:eth2",
                "affected_routers": ["spine2", "leaf2"],
                "affected_interfaces": ["spine2:eth2"],
                "affected_prefixes": [],
                "confidence": 0.88,
                "reasoning": "LLM mock reasoning",
                "remediation": "Bring interface up",
                "diagnosis_time_ms": 215,
            },
            "rule_based_correct_class": False,
            "rule_based_correct_location": False,
            "llm_correct_class": True,
            "llm_correct_location": True,
        },
    ]

    results_path.write_text(json.dumps(results, indent=2))
    trials_path.write_text(json.dumps(trials, indent=2))

    print(f"Wrote {results_path}")
    print(f"Wrote {trials_path}")
    print("You can now run: python dashboard.py")


if __name__ == "__main__":
    main()
