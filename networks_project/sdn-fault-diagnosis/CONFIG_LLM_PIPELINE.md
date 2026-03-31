# LLM-Assisted Config Change Pipeline (Plan)

Goal: demonstrate that an LLM can propose, validate, and apply FRR/Containerlab config fixes safely, with measurable accuracy and impact.

## Components
1) **Config linter/validator**  
   - Add a Python helper (e.g., `config/validator.py`) that runs FRR `vtysh -f <file>` or `vtysh -c "conf t"` in a throwaway container (or `containerlab deploy --dry-run`) to surface syntax and semantic errors.  
   - Include lightweight static checks: missing network statements, wrong OSPF area, auth/key mismatch, interface mismatch, duplicate router-ids.
2) **LLM planner**  
   - Module (e.g., `config/llm_planner.py`) that ingests current config + intent + validation errors, and outputs a minimal diff/patch.  
   - Prompt: instructions to propose unified diffs only, within a schema; include constraints (no passwords), target device, and intents.
   - Safety: require JSON schema with `patch` and `reasoning`; run schema validation before applying.
3) **Synthetic config-error scenarios**  
   - Curate fixtures under `tests/fixtures/config_errors/` with known bad configs and ground-truth fixes:  
     - Wrong area ID, missing `network` statement, OSPF auth/key mismatch, interface name typo, missing loopback, duplicate router-id, bad route-map.  
   - Provide an intent file per scenario (YAML/JSON) describing desired state to guide the LLM.
4) **Conformance checks**  
   - After applying a candidate patch to a temp config, re-run validator and compare running state vs intent: all neighbors Full, expected LSAs/routes present, auth enabled where required.  
   - Capture before/after config and diff; store in `evaluation/config_runs/`.
5) **CLI harness**  
   - `python -m config.runner --scenario ospf_area_mismatch --llm`  
   - Modes: `--lint-only`, `--llm-plan`, `--apply` (to temp sandbox), `--score`.

## Evaluation Metrics
- Patch correctness: exact match to ground-truth fix; partial credit for resolving validation errors.  
- Conformance: intent satisfied (neighbors Full, LSAs/prefixes present, auth state correct).  
- Safety: no new validation errors; no removal of unrelated config; size of diff.  
- Latency and token cost per run; LLM vs deterministic baseline (rule-based suggestions).  
- Success under noise: missing interfaces, extra stanzas, reordered configs.

## Workflow (per scenario)
1) Load bad config + intent.  
2) Run validator -> collect errors and state deltas (expected vs actual).  
3) LLM planner produces JSON with patch + reasoning.  
4) Apply patch to a temp copy of config.  
5) Re-run validator and conformance checks.  
6) Record results (before/after, diff, metrics, logs).

## Testing
- Unit: validator catches each synthetic error; planner JSON schema validation.  
- Integration: end-to-end scenario run resolves errors and meets intent; regression snapshots for diffs.  
- CI: run `pytest tests/test_config_pipeline.py` with `--mock-llm` fixtures; gate LLM tests behind env var.

## Integration Points
- Reuse telemetry collector for conformance (neighbors/routes).  
- Optionally invoke the LLM only when validator cannot auto-fix deterministically (hybrid cost savings).  
- Log prompt, model id, prompt hash, and parsed output per run for reproducibility.
