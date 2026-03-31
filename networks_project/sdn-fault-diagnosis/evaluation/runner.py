#!/usr/bin/env python3
"""
Experiment runner for SDN fault diagnosis evaluation.

Orchestrates the complete experimental workflow:
1. Verify healthy network baseline
2. Inject faults (randomized or from scenarios)
3. Collect post-fault telemetry
4. Run both diagnostic engines
5. Record and compare results

Usage:
    python runner.py --trials 100
    python runner.py --trials 10 --compound-ratio 0.2
    python runner.py --scenario spine1_leaf1_link_down
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional
from uuid import uuid4

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from telemetry.schemas import DiagnosisResult, NetworkSnapshot, TrialResult
from telemetry.collector import TelemetryCollector
from telemetry.snapshot import SnapshotManager

from faults.injector import FaultInjector
from faults.fault_types import FaultClass
from faults.scenarios import (
    ALL_SCENARIOS,
    Scenario,
    get_balanced_scenario_set,
    generate_random_scenario,
)

from diagnosis.rule_based import RuleBasedEngine
from diagnosis.llm_agent import LLMAgent, MockLLMAgent
from diagnosis.ml_engine import MLEngine
from diagnosis.hybrid_engine import HybridEngine

from .metrics import MetricsComputer
from .stats import run_all_tests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Constants
DEFAULT_CONTAINER_PREFIX = "clab-sdn-fault-diagnosis"
OSPF_HELLO_INTERVAL = 10  # seconds
CONVERGENCE_WAIT = 12  # seconds (hello + poll cycle)


class ExperimentRunner:
    """
    Runs fault diagnosis experiments.

    Coordinates fault injection, telemetry collection, and diagnosis
    to produce comparable results from rule-based and LLM engines.
    """

    def __init__(
        self,
        container_prefix: str = DEFAULT_CONTAINER_PREFIX,
        output_dir: Path = None,
        use_mock_llm: bool = False,
        use_ml_engine: bool = False,
        ml_model_path: Path = None,
        llm_model: str = None,
    ):
        """
        Initialize the experiment runner.

        Args:
            container_prefix: Containerlab container name prefix
            output_dir: Directory for results output
            use_mock_llm: Use mock LLM for testing without API
            use_ml_engine: Include ML engine in evaluation
            ml_model_path: Path to trained ML model file
            llm_model: Override LLM model ID (e.g. claude-haiku-4-5-20251001)
        """
        self.container_prefix = container_prefix
        self.output_dir = output_dir or Path("./evaluation/results")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize components
        self.collector = TelemetryCollector(container_prefix=container_prefix)
        self.snapshot_manager = SnapshotManager(self.output_dir / "snapshots")
        self.injector = FaultInjector(container_prefix=container_prefix)

        # Initialize diagnostic engines
        self.rule_based = RuleBasedEngine()

        if use_mock_llm:
            logger.info("Using mock LLM agent (no API calls)")
            self.llm_agent = MockLLMAgent()
        else:
            try:
                kwargs = {}
                if llm_model:
                    kwargs["model"] = llm_model
                self.llm_agent = LLMAgent(**kwargs)
                logger.info(f"LLM agent initialized with model: {self.llm_agent.model}")
            except ValueError as e:
                logger.warning(f"LLM agent init failed: {e}")
                logger.info("Falling back to mock LLM agent")
                self.llm_agent = MockLLMAgent()

        # ML engine (optional)
        self.ml_engine = None
        self.use_ml_engine = use_ml_engine
        if use_ml_engine:
            try:
                self.ml_engine = MLEngine(model_path=ml_model_path)
                logger.info("ML engine initialized")
            except (FileNotFoundError, ImportError) as e:
                logger.warning(f"ML engine init failed: {e}")
                self.use_ml_engine = False

        # Hybrid engine (always available — uses rule_based + llm_agent)
        self.hybrid_engine = HybridEngine(
            rule_engine=RuleBasedEngine(),  # separate instance to avoid shared state
            llm_engine=self.llm_agent,
        )
        logger.info(
            f"Hybrid engine initialized (threshold={self.hybrid_engine.confidence_threshold})"
        )

        # Metrics tracking
        self.metrics = MetricsComputer()
        self.trials: list[TrialResult] = []
        self.use_mock_llm = use_mock_llm

    def verify_network_health(self) -> bool:
        """
        Verify the network is healthy before experimentation.

        Checks:
        - All containers are running
        - All OSPF adjacencies are Full
        - End-to-end connectivity

        Returns:
            True if network is healthy
        """
        logger.info("Verifying network health...")

        # Collect baseline snapshot
        try:
            snapshot = self.collector.collect_snapshot()
        except Exception as e:
            logger.error(f"Failed to collect snapshot: {e}")
            return False

        if len(snapshot.routers) < 8:
            logger.error(
                f"Missing routers: expected 8, got {len(snapshot.routers)}"
            )
            return False

        # Check adjacencies
        total_expected = 32  # 4 spines * 4 leafs = 16 bidirectional = 32 total
        total_full = snapshot.total_full_adjacencies

        if total_full < total_expected:
            logger.error(
                f"Adjacencies not Full: {total_full}/{total_expected}"
            )

            # Log which neighbors are not Full
            for router_name, telemetry in snapshot.routers.items():
                for neighbor in telemetry.non_full_adjacencies:
                    logger.warning(
                        f"{router_name}: neighbor {neighbor.neighbor_id} "
                        f"in state {neighbor.state}"
                    )

            return False

        logger.info(
            f"Network healthy: {len(snapshot.routers)} routers, "
            f"{total_full} Full adjacencies"
        )

        return True

    def wait_for_convergence(self, seconds: float = CONVERGENCE_WAIT):
        """Wait for OSPF convergence after fault injection."""
        logger.debug(f"Waiting {seconds}s for OSPF convergence...")
        time.sleep(seconds)

    def run_single_trial(
        self,
        scenario: Optional[Scenario] = None,
        fault_class: Optional[FaultClass] = None,
    ) -> TrialResult:
        """
        Run a single experimental trial.

        Args:
            scenario: Specific scenario to run, or None for random
            fault_class: Specific fault class, or None for random

        Returns:
            TrialResult with ground truth and diagnoses
        """
        trial_id = f"trial_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid4().hex[:8]}"
        logger.info(f"Starting trial: {trial_id}")

        # Collect pre-fault snapshot
        pre_fault_snapshot = self.collector.collect_snapshot()
        self.snapshot_manager.save(pre_fault_snapshot)

        # Inject fault
        if scenario:
            ground_truth = self._inject_scenario(scenario)
        else:
            _, _, ground_truth = self.injector.inject_random_fault(fault_class)

        # Wait for convergence
        self.wait_for_convergence()

        # Collect post-fault snapshot
        post_fault_snapshot = self.collector.collect_snapshot()
        self.snapshot_manager.save(post_fault_snapshot)

        # Run all diagnostic engines
        logger.info("Running rule-based diagnosis...")
        rb_diagnosis = self.rule_based.diagnose_with_history(post_fault_snapshot)

        logger.info("Running LLM diagnosis...")
        llm_diagnosis = self.llm_agent.diagnose_with_history(post_fault_snapshot)

        ml_diagnosis = None
        if self.ml_engine:
            logger.info("Running ML diagnosis...")
            ml_diagnosis = self.ml_engine.diagnose_with_history(post_fault_snapshot)

        logger.info("Running hybrid diagnosis...")
        hybrid_diagnosis = self.hybrid_engine.diagnose_with_history(post_fault_snapshot)

        # Restore faults
        self.injector.restore_all()
        self.wait_for_convergence()

        # Create trial result
        trial = TrialResult(
            trial_id=trial_id,
            timestamp=datetime.utcnow(),
            injected_fault_type=ground_truth["fault_class"],
            injected_fault_location=ground_truth.get("location", ""),
            injected_fault_params=ground_truth,
            pre_fault_snapshot_id=pre_fault_snapshot.snapshot_id,
            post_fault_snapshot_id=post_fault_snapshot.snapshot_id,
            rule_based_diagnosis=rb_diagnosis,
            llm_diagnosis=llm_diagnosis,
            ml_diagnosis=ml_diagnosis,
            hybrid_diagnosis=hybrid_diagnosis,
            rule_based_correct_class=(
                rb_diagnosis.fault_class == ground_truth["fault_class"]
            ),
            rule_based_correct_location=(
                rb_diagnosis.location == ground_truth.get("location")
            ),
            llm_correct_class=(
                llm_diagnosis.fault_class == ground_truth["fault_class"]
            ),
            llm_correct_location=(
                llm_diagnosis.location == ground_truth.get("location")
            ),
            ml_correct_class=(
                ml_diagnosis.fault_class == ground_truth["fault_class"]
                if ml_diagnosis else False
            ),
            ml_correct_location=(
                ml_diagnosis.location == ground_truth.get("location")
                if ml_diagnosis else False
            ),
            hybrid_correct_class=(
                hybrid_diagnosis.fault_class == ground_truth["fault_class"]
            ),
            hybrid_correct_location=(
                hybrid_diagnosis.location == ground_truth.get("location")
            ),
        )

        # Log results
        ml_str = ""
        if ml_diagnosis:
            ml_str = (
                f", ml={ml_diagnosis.fault_class} "
                f"({'✓' if trial.ml_correct_class else '✗'})"
            )
        logger.info(
            f"Trial {trial_id} complete: "
            f"ground_truth={ground_truth['fault_class']}, "
            f"rule_based={rb_diagnosis.fault_class} "
            f"({'✓' if trial.rule_based_correct_class else '✗'}), "
            f"llm={llm_diagnosis.fault_class} "
            f"({'✓' if trial.llm_correct_class else '✗'})"
            f"{ml_str}, "
            f"hybrid={hybrid_diagnosis.fault_class} "
            f"({'✓' if trial.hybrid_correct_class else '✗'})"
        )

        return trial

    def _inject_scenario(self, scenario: Scenario) -> dict:
        """
        Inject all faults from a scenario.

        Args:
            scenario: Scenario to inject

        Returns:
            Ground truth dict
        """
        logger.info(f"Injecting scenario: {scenario.name}")

        ground_truth = {
            "fault_class": scenario.faults[0].fault_class.value,
            "scenario": scenario.name,
            "compound": scenario.is_compound,
        }

        for fault_spec in scenario.faults:
            config = fault_spec.to_dict()
            config["container_prefix"] = self.container_prefix

            if fault_spec.fault_class == FaultClass.LINK_FAILURE:
                self.injector.inject_link_failure(
                    fault_spec.container,
                    fault_spec.params["interface"]
                )
                ground_truth["location"] = (
                    f"{fault_spec.container}:{fault_spec.params['interface']}"
                )

            elif fault_spec.fault_class == FaultClass.FLAPPING_LINK:
                self.injector.inject_flapping_link(
                    fault_spec.container,
                    fault_spec.params["interface"],
                    period_sec=fault_spec.params.get("period_sec", 5.0),
                    count=fault_spec.params.get("count", 3)
                )
                ground_truth["location"] = (
                    f"{fault_spec.container}:{fault_spec.params['interface']}"
                )

            elif fault_spec.fault_class == FaultClass.STALE_ROUTE:
                self.injector.inject_stale_route(
                    fault_spec.container,
                    fault_spec.params["prefix"],
                    fault_spec.params["nexthop"],
                    distance=fault_spec.params.get("distance", 1)
                )
                ground_truth["location"] = (
                    f"{fault_spec.container}:{fault_spec.params['prefix']}"
                )

            elif fault_spec.fault_class == FaultClass.MISSING_ROUTE:
                self.injector.inject_missing_route(
                    fault_spec.container,
                    fault_spec.params["prefix"],
                    area=fault_spec.params.get("area", "0")
                )
                ground_truth["location"] = (
                    f"{fault_spec.container}:{fault_spec.params['prefix']}"
                )

            elif fault_spec.fault_class == FaultClass.COUNTER_ANOMALY:
                self.injector.inject_counter_anomaly(
                    fault_spec.container,
                    fault_spec.params["interface"],
                    loss_pct=fault_spec.params.get("loss_pct", 5.0),
                    corrupt_pct=fault_spec.params.get("corrupt_pct", 0.0)
                )
                ground_truth["location"] = (
                    f"{fault_spec.container}:{fault_spec.params['interface']}"
                )

        return ground_truth

    def run_experiment(
        self,
        num_trials: int = 100,
        compound_ratio: float = 0.2,
        verify_before: bool = True,
    ) -> dict:
        """
        Run a complete experiment with multiple trials.

        Args:
            num_trials: Total number of trials to run
            compound_ratio: Ratio of compound fault trials
            verify_before: Verify network health before starting

        Returns:
            Dict with experiment results
        """
        experiment_id = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        start_time = datetime.utcnow()
        logger.info(
            f"Starting experiment {experiment_id}: "
            f"{num_trials} trials, {compound_ratio:.0%} compound"
        )

        if verify_before:
            if not self.verify_network_health():
                logger.error("Network health check failed - aborting")
                return {"error": "Network health check failed"}

        # Generate balanced scenario set
        scenarios = get_balanced_scenario_set(num_trials, compound_ratio)

        # Run trials
        start_time = time.time()

        for i, scenario in enumerate(scenarios):
            logger.info(f"Trial {i+1}/{num_trials}")

            try:
                trial = self.run_single_trial(scenario=scenario)
                self.trials.append(trial)
                self.metrics.add_trial(trial)

                # Save intermediate results every 10 trials
                if (i + 1) % 10 == 0:
                    self._save_intermediate_results(experiment_id)

            except Exception as e:
                logger.error(f"Trial {i+1} failed: {e}")
                # Try to restore and continue
                self.injector.restore_all()
                time.sleep(5)

        elapsed = time.time() - start_time

        # Generate final results
        llm_stats = self.llm_agent.get_stats() if hasattr(self.llm_agent, "get_stats") else {}
        rb_stats = self.rule_based.get_stats() if hasattr(self.rule_based, "get_stats") else {}

        results = {
            "experiment_id": experiment_id,
            "num_trials": len(self.trials),
            "elapsed_seconds": elapsed,
            "metrics": self.metrics.get_comparison(),
            "per_class": self.metrics.get_per_class_metrics(),
            "statistical_tests": run_all_tests(self.trials),
            "run_metadata": {
                "experiment_id": experiment_id,
                "trials_requested": num_trials,
                "compound_ratio": compound_ratio,
                "use_mock_llm": self.use_mock_llm,
                "start_time": start_time.isoformat(),
                "llm_model": llm_stats.get("model"),
                "llm_prompt_hash": llm_stats.get("prompt_hash"),
                "llm_temperature": llm_stats.get("temperature"),
                "llm_invocations": len(self.trials),
                "llm_total_input_tokens": llm_stats.get("total_input_tokens", 0),
                "llm_total_output_tokens": llm_stats.get("total_output_tokens", 0),
                "llm_num_few_shot_examples": llm_stats.get("num_few_shot_examples", 0),
                "rule_based_name": rb_stats.get("name", "rule-based"),
            },
        }

        # Save results
        self._save_results(experiment_id, results)

        logger.info(
            f"Experiment {experiment_id} complete: "
            f"{len(self.trials)} trials in {elapsed:.1f}s"
        )

        return results

    def _save_intermediate_results(self, experiment_id: str):
        """Save intermediate results during experiment."""
        filepath = self.output_dir / f"intermediate_{experiment_id}.json"
        results = {
            "experiment_id": experiment_id,
            "trials_completed": len(self.trials),
            "metrics": self.metrics.get_comparison(),
        }
        with open(filepath, "w") as f:
            json.dump(results, f, indent=2, default=str)

    def _save_results(self, experiment_id: str, results: dict):
        """Save final experiment results."""
        # Save summary
        summary_path = self.output_dir / f"results_{experiment_id}.json"
        with open(summary_path, "w") as f:
            json.dump(results, f, indent=2, default=str)
        logger.info(f"Results saved to {summary_path}")

        # Save detailed trials
        trials_path = self.output_dir / f"trials_{experiment_id}.json"
        trials_data = [t.model_dump() for t in self.trials]
        with open(trials_path, "w") as f:
            json.dump(trials_data, f, indent=2, default=str)
        logger.info(f"Trial details saved to {trials_path}")


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Run SDN fault diagnosis experiments"
    )

    parser.add_argument(
        "--trials",
        type=int,
        default=100,
        help="Number of trials to run (default: 100)"
    )
    parser.add_argument(
        "--compound-ratio",
        type=float,
        default=0.2,
        help="Ratio of compound fault trials (default: 0.2)"
    )
    parser.add_argument(
        "--scenario",
        type=str,
        help="Run a specific scenario by name"
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("./evaluation/results"),
        help="Output directory for results"
    )
    parser.add_argument(
        "--prefix",
        type=str,
        default=DEFAULT_CONTAINER_PREFIX,
        help="Container name prefix"
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Override LLM model ID (e.g. claude-haiku-4-5-20251001, claude-sonnet-4-5-20250929)"
    )
    parser.add_argument(
        "--mock-llm",
        action="store_true",
        help="Use mock LLM (no API calls)"
    )
    parser.add_argument(
        "--ml-engine",
        action="store_true",
        help="Include ML engine (Random Forest) in evaluation"
    )
    parser.add_argument(
        "--ml-model-path",
        type=Path,
        default=None,
        help="Path to trained ML model (default: models/rf_fault_classifier.joblib)"
    )
    parser.add_argument(
        "--skip-health-check",
        action="store_true",
        help="Skip initial health check"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    runner = ExperimentRunner(
        container_prefix=args.prefix,
        output_dir=args.output,
        use_mock_llm=args.mock_llm,
        use_ml_engine=args.ml_engine,
        ml_model_path=args.ml_model_path,
        llm_model=args.model,
    )

    if args.scenario:
        # Run single scenario
        scenario = next(
            (s for s in ALL_SCENARIOS if s.name == args.scenario),
            None
        )
        if not scenario:
            print(f"Unknown scenario: {args.scenario}")
            print("Available scenarios:")
            for s in ALL_SCENARIOS:
                print(f"  - {s.name}: {s.description}")
            sys.exit(1)

        if not args.skip_health_check:
            if not runner.verify_network_health():
                print("Network health check failed")
                sys.exit(1)

        trial = runner.run_single_trial(scenario=scenario)
        print(f"\nTrial: {trial.trial_id}")
        print(f"Ground truth: {trial.injected_fault_type} at {trial.injected_fault_location}")
        print(f"Rule-based: {trial.rule_based_diagnosis.fault_class} "
              f"({'✓' if trial.rule_based_correct_class else '✗'})")
        print(f"LLM: {trial.llm_diagnosis.fault_class} "
              f"({'✓' if trial.llm_correct_class else '✗'})")

    else:
        # Run full experiment
        results = runner.run_experiment(
            num_trials=args.trials,
            compound_ratio=args.compound_ratio,
            verify_before=not args.skip_health_check,
        )

        # Print summary
        if "error" not in results:
            print("\n" + "=" * 60)
            print("EXPERIMENT RESULTS")
            print("=" * 60)
            print(f"Trials: {results['num_trials']}")
            print(f"Time: {results['elapsed_seconds']:.1f}s")
            print()
            print("Classification Accuracy:")
            print(f"  Rule-based: {results['metrics']['rule_based']['classification']['accuracy']:.1%}")
            print(f"  LLM Agent:  {results['metrics']['llm_agent']['classification']['accuracy']:.1%}")
            print()
            print("Statistical Tests:")
            mcnemar = results['statistical_tests']['mcnemar_classification']
            print(f"  McNemar's test: p={mcnemar['p_value']:.4f} "
                  f"({'significant' if mcnemar['significant'] else 'not significant'})")


if __name__ == "__main__":
    main()
