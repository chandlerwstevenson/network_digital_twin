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
- endpoint smoke suite currently passes (`26 passed`)
- export endpoint coverage now includes Jira, ServiceNow, and generic webhook delivery for non-native ITSM targets
- export URL validation now rejects malformed Jira/ServiceNow/webhook destinations instead of attempting bad outbound calls
- export responses now surface aggregate delivery health (`export_status`, attachment success/failure counts, comment/webhook delivery flags) so partial ITSM handoff failures are explicit instead of implicit

Next target:
- add abuse/size guardrail tests for `/api/batch-review`
- add more endpoint-level assertions around pipeline webhook payload shape and blocking thresholds
- expand negative-path coverage around ServiceNow-specific export failures and malformed auth combinations

### 2. ITSM UX in the web app
Requirements:
- REQ-3.4.6 direct export integration
- REQ-3.6.4 ServiceNow and Jira Cloud integration

Target:
- add one-click export actions in `apps/web`
- capture Jira/ServiceNow/webhook destination details without forcing manual JSON editing
- surface attachment/export status clearly for change-window workflows

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
