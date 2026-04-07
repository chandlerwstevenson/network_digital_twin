# Config Studio Structured Work Loop

Use `REQUIREMENT.txt` as the source of truth.

## Loop

For each work pass:

1. Re-read the relevant requirement sections before coding.
2. Pick the single highest-leverage unmet MVP item.
3. Implement code, not just notes.
4. Update memory with what changed.
5. Stop and reassess the next highest-leverage gap.

## Current priority order

### 1. Validation depth for live engine flows
Requirements:
- REQ-3.1.5 API endpoint for CI/CD integration
- REQ-3.4.6 direct export integration
- REQ-3.6.2 webhook notifications
- REQ-3.6.4 ServiceNow and Jira Cloud integration

Status update (2026-04-07):
- real FastAPI/Pydantic/Pytest runtime is now working locally under Python 3.13 in repo venv `.venv313`
- endpoint smoke suite currently passes (`28 passed`)
- export endpoint coverage now includes Jira, ServiceNow, and generic webhook delivery for non-native ITSM targets
- export URL validation now rejects malformed Jira/ServiceNow/webhook destinations instead of attempting bad outbound calls
- export responses now surface aggregate delivery health (`export_status`, attachment success/failure counts, comment/webhook delivery flags) so partial ITSM handoff failures are explicit instead of implicit
- `/api/batch-review` now enforces the 2 MB per-config limit from REQ-3.1.2 during ZIP extraction, rejects oversized archives with too many members, and has live smoke coverage for those abuse/size guardrails

Next target:
- add more endpoint-level assertions around pipeline webhook payload shape and blocking thresholds
- expand negative-path coverage around ServiceNow-specific export failures and malformed auth combinations
- consider whether `/api/batch-review` should also expose explicit archive-level size metadata back to the UI for clearer operator feedback

### 2. ITSM UX in the web app
Requirements:
- REQ-3.4.6 direct export integration
- REQ-3.6.4 ServiceNow and Jira Cloud integration

Status update (2026-04-07):
- the web app now exposes one-click export handoff for Jira Cloud, ServiceNow, and generic webhook targets
- destination details, artifact selection, webhook payload toggles, and webhook headers can now be captured in the operator UI without dropping into curl or manual JSON request editing
- batch triage progress now records webhook exports distinctly instead of forcing everything into a Jira/ServiceNow label
- the ZIP triage queue now has a direct `Export to ITSM` action per review, so an operator can hand off a queued device without first opening it in the main workspace
- each review now keeps a session-scoped export history with target/destination/status metadata in both the main export panel and the batch queue cards, making long maintenance-window handoff tracking much less guessy
- batch review cards now surface the last failed/partial export's component-level details (artifact/comment/webhook) plus concrete retry guidance, so change-window operators do not have to open the full review just to see why a handoff failed
- the ZIP triage queue now shows the current handoff destination at the top, can export the next pending review straight to that current target, can retry the first failed export from the queue, and can copy a manual fallback package per review or for the first blocked/failing item when the remote ITSM system is degraded

Next target:
- add tighter per-review duplicate helpers for repeated same-ticket handoffs (for example, clone the last successful destination/comment bundle onto another card without touching the main export panel)
- consider local download of a fuller manual-fallback bundle (for example, JSON + handoff note together) when the remote ITSM system is down during an active window
- then return to backend guardrails for `/api/batch-review` and pipeline webhook-shape assertions

### 3. Findings quality
Requirements:
- REQ-3.3.3 semantic analysis
- REQ-3.3.4 security checks
- REQ-3.3.5 finding output format

Target:
- improve line attribution
- reduce false positives
- strengthen JunOS coverage
- ensure findings consistently include useful remediation/rollback/context

### 4. Persistence
Requirements:
- REQ-3.4.7 report retention
- REQ-3.11 history/versioning (later)
- query history requirements

Target:
- save reviews/findings/query history once local flow is stable

## Rules from Chandler
- Reference `REQUIREMENT.txt` every pass.
- Update memory every pass.
- Prioritize writing code over commit/repo hygiene.
