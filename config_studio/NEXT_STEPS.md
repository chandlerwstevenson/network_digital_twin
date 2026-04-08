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
- endpoint smoke suite currently passes (`32 passed`)
- export endpoint coverage now includes Jira, ServiceNow, and generic webhook delivery for non-native ITSM targets
- export URL validation now rejects malformed Jira/ServiceNow/webhook destinations instead of attempting bad outbound calls
- export responses now surface aggregate delivery health (`export_status`, attachment success/failure counts, comment/webhook delivery flags) so partial ITSM handoff failures are explicit instead of implicit
- `/api/batch-review` now enforces the 2 MB per-config limit from REQ-3.1.2 during ZIP extraction, rejects oversized archives with too many members, and has live smoke coverage for those abuse/size guardrails
- `/api/pipeline/review` now validates `webhook_url` as a real http(s) destination before attempting delivery and sends a more structured webhook payload (`event`, `gate`, `summary`, `blocking_findings`, optional `review`) so CI consumers can parse it without guessing field semantics
- runtime smoke coverage now explicitly asserts pipeline webhook payload shape, threshold gating via `max_blocking_findings`, invalid pipeline webhook URL rejection, and ServiceNow export negative paths for malformed auth / invalid instance URL
- `/api/batch-review` now returns explicit ZIP intake metadata (`archive_summary`) so the web UI can show how many archive members were actually reviewed versus skipped, how much config text was ingested, and sample skipped filenames/reasons when sidecar docs, empty files, or other junk were ignored
- `/api/batch-review` no longer rejects sidecar-heavy ZIPs just because the raw archive member count is high; it now tolerates up to 1000 total entries while enforcing the real product limit of 50 readable configs per upload, which closes the earlier blunt edge where README/checklist-heavy bundles could be rejected before filtering

Next target:
- either explicitly justify/test the unrelated `http://127.0.0.1:3000` CORS widening in engine config or revert it so this backend slice stays requirement-focused
- then return to findings-quality depth (especially line attribution / false-positive reduction / stronger JunOS coverage)

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
- the ZIP triage queue now also tracks the last successful handoff bundle in-session and can duplicate that destination/comment/artifact setup directly onto another queued review or the next pending review without forcing the operator back through the main export panel
- the web UI now supports local download of a fuller manual-fallback bundle for both the main review and ZIP triage queue: one click saves a `.json` bundle (handoff summary, fallback note, latest export failure metadata, full report payload) plus a matching `.txt` operator note so a network engineer can keep the maintenance window moving even if Jira/ServiceNow/webhooks are degraded
- the batch-review UI now surfaces a ZIP intake summary panel so operators can immediately see how many archive entries were actually reviewed, how much config text was ingested, whether cross-config correlation ran, and which sample files were skipped because they were empty or did not look like network configs

Next target:
- stale-vs-current duplicated-handoff labeling is now implemented directly on the batch queue and per-review cards, so operators can see when a reusable destination no longer matches the export panel target
- batch triage queue now also has operator-focused filter/search controls so medium-size ZIP reviews can be narrowed to needs-attention / critical / failing / pending / export-issue subsets and searched by filename, hostname, vendor, finding title, or destination during a live change window
- queue-level batch quick actions now respect the visible filtered/search slice instead of acting on hidden reviews elsewhere in the queue, which removes a real change-window footgun when an engineer narrows to a subset and expects “next pending” / “retry first failed” to stay inside that slice
- the analysis workspace now includes a batch queue navigator when a review is opened from a ZIP batch, so the engineer can move previous/next within the current visible slice and use a one-click `mark done + open next pending` flow without bouncing back down to the batch panel after every device
- single-file upload intake now surfaces filename/size/line-count status, supports more real export suffixes (`.config`, `.cnf`, `.bak`), and warns before analysis when the selected file is empty, oversized (>2 MB), binary-looking, or otherwise suspicious instead of silently stuffing it into the workspace
- return to backend validation depth for ServiceNow partial-failure coverage and export/reporting depth
- after that, consider whether the batch queue should expose more pre-review ZIP linting before upload (for example, warn locally on obviously empty sidecar-heavy archives)

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
