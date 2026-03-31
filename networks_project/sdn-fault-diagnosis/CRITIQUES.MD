# Critiques and Improvement Plan

Status key: [DONE] = addressed, [PARTIAL] = partially addressed, [OPEN] = not yet addressed

## Evidence for LLM Value
- [DONE] Only one weak baseline (handwritten tree); add stronger comparators (feature-based ML, heuristic ensembles) to show LLM lift.
  → Added ML engine (Random Forest + Gradient Boosting, calibrated) and hybrid engine (rule-based + LLM defer)
- [DONE] Metrics miss calibration, robustness to noise/partial data, and cost/latency trade-offs; include reliability curves and selective-prediction metrics.
  → Added bootstrap 95% CIs, Cohen's h effect sizes, Brier scores, cost-per-diagnosis/cost-per-correct metrics, pairwise comparisons for all 4 engines
- [DONE] Prompts/examples are static and unvalidated; no prompt ablations or curated few-shot coverage.
  → Expanded to 8 few-shot examples covering all 5 fault classes + no_fault + 2 ambiguous edge cases
- [OPEN] JSON parsing is brittle; lacks schema enforcement or structured self-correction.
- [PARTIAL] Scenarios are synthetic/fixed; no noisy telemetry, config drift, or real SDN failure patterns.
  → ML training data includes realistic noise, cascading effects, severity bands, and confusable examples

## Fault Modeling
- [OPEN] Taxonomy is narrow (5 faults); missing CPU/memory exhaustion, MTU mismatches, policy/route-map errors, BFD flaps, ECMP imbalance, ACL drops, VLAN/tag issues, timer mismatches, DHCP/ARP anomalies.
- [OPEN] Limited compound/adversarial cases; few slow-burn or intermittent faults; minimal telemetry-gaps handling.
- [OPEN] Telemetry sources are only vtysh JSON; no flow records, pcaps, or controller intent/state to back "holistic" claims.

## Experiment Design
- [OPEN] No train/validation split for prompt tuning; risk of leakage/overfit.
- [OPEN] Single topology (4x4 spine–leaf); no cross-topology/scale tests.
- [DONE] No power analysis; p-values without confidence intervals/effect sizes; cost not tied to outcomes.
  → Bootstrap CIs, Cohen's h, cost analysis, all 6 pairwise comparisons across 4 engines
- [OPEN] Fault injector verification is shallow; does not confirm injected state matches ground truth.
- [OPEN] Recovery impact not measured; only time-to-diagnosis, not time-to-restore/misdiagnosis cost.

## LLM Agent
- [DONE] No diff-aware prompts; ignores previous vs current snapshot context.
  → diagnose() computes SnapshotDiff, includes structured diff JSON in prompt
- [DONE] Few-shot set may not cover all classes or ambiguous/no-fault cases; lacks red-team/edge examples.
  → 8 examples: all 5 classes + no_fault + borderline counter anomaly + link failure with flapping history
- [DONE] Prompt/response artifacts are not logged with hashes/model versions for reproducibility.
  → Artifact logging: model, prompt_hash, input/output tokens, latency, stop_reason per invocation
- [DONE] Single-model dependency; no portability/variance study across providers or versions.
  → Model configurable via constructor, env var LLM_MODEL, or CLI --model

## Rule-Based and Hybrid Baselines
- [DONE] Deterministic engine is a simple tree; add feature extraction + classical ML and hybrids (rule prefilter + LLM fallback).
  → ML engine with 290 features (per-router + cross-router + aggregate), RF/GB comparison, calibration
- [DONE] No confidence-based abstain/defer logic to manage cost and risk.
  → Hybrid engine: rule-based triage, defer to LLM when confidence < threshold (default 0.80)

## Config-Authoring Use Case
- [DONE] No pipeline to prove LLM-driven config fixes: missing lint/dry-run validation, intent checks, or synthetic config-error scenarios.
  → 6 config-error scenarios: area mismatch, missing network, missing router-id, duplicate router-id, interface typo, missing auth. Full pipeline with validator + mock/LLM planner + re-validation
- [DONE] No automated conformance checks comparing desired vs actual state after LLM suggestions.
  → Pipeline re-validates patched config against intent, reports pass/fail conformance

## Robustness and Operations
- [OPEN] Collector is OrbStack-dependent; portability to plain Docker/K8s not demonstrated.
- [OPEN] Collector lacks retries/health flags; partial failures silently reduce coverage.
- [OPEN] Snapshot diff ignores counter deltas over time; can mis-score transient issues.
- [OPEN] Secrets handling is basic; API key management guidance absent.
- [OPEN] No CI for tests/linters or mock experiment runs.

## Reporting and Dashboard
- [DONE] Results JSON lacks run metadata (model id, prompt hash, cost, latency percentiles); weakens comparisons.
  → run_metadata includes model, prompt_hash, tokens, few-shot count
- [DONE] Dashboard lacks confidence intervals and cost/time overlays; not publishable as static artifact.
  → 4-engine dashboard with accuracy + CI bars, cost-per-correct chart, pairwise stats table, hybrid panel, timing comparison

## Highest-Impact Next Steps
1) [DONE] Broaden scenarios and telemetry noise; add stronger ML/hybrid baselines with effect sizes, CIs, and cost/latency metrics.
2) [DONE] Harden LLM agent: schema validation, diff-aware prompts, curated few-shots (including no-fault/ambiguous), logged artifacts, and selective invocation.
3) [DONE] Add config-error scenarios plus an LLM-assisted fix loop with dry-run/linting and intent conformance checks.
4) [OPEN] Test across topologies/scales and under missing/partial telemetry to demonstrate generalization and robustness.
