# Optimesh Config Studio

Config Studio is a network configuration review product prototype.

Current repo contents:
- `apps/engine` — FastAPI analysis engine for config review
- `apps/desktop` — Electron shell that embeds the engine and a static renderer
- `apps/web` — working static frontend for review, query, batch review, template authoring, compare, and operator workflows
- `packages/shared` — shared TypeScript domain types
- `supabase/` — schema and backend data model draft
- `examples/` — CI/CD and ITSM integration examples for GitHub Actions, GitLab CI, Jenkins, Jira Cloud, ServiceNow, and a local shell gate

## Status

This repository is now a **working end-to-end prototype**, not just an engine stub.

The current implementation covers the day-one web flow plus a pipeline-oriented REST gate for pre-merge / pre-deploy review and direct export hooks for Jira Cloud / ServiceNow change records. See `REQUIREMENT.txt` for product targets and `NEXT_STEPS.md` for the current structured work loop.

## Engine development

### Requirements
- Python 3.11+ (validated locally with Python 3.13)

### Setup
```bash
cd apps/engine
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run
```bash
cd apps/engine
python3 -m uvicorn app.main:app --reload --port 8000
```

### Test
```bash
cd apps/engine
python3 -m pytest -q
```

Validated locally on 2026-04-07:
- `npm run build --workspace apps/web`
- `python3 -m py_compile apps/engine/app/api/routes.py apps/engine/app/api/schemas.py apps/engine/app/parsers/detector.py apps/engine/tests/test_api_smoke.py`
- `../../.venv313/bin/pytest -q` from `apps/engine` → `20 passed`

## Desktop app

The desktop app expects a built static renderer under the web app output path.
Desktop packaging is still incomplete, but it now targets the implemented `apps/web` static frontend rather than a missing renderer.

## Pipeline review endpoint

Config Studio now exposes a CI/CD-friendly gate endpoint:

```bash
POST /api/pipeline/review
```

It wraps the normal analyzer and returns a merge/deploy decision shaped for automation:
- `gate_status`: `pass` or `block`
- `should_block`: boolean exit signal for pipelines
- `blocking_findings`: findings at or above the requested severity threshold
- `summary`: compact metadata for logs and pipeline annotations
- optional webhook delivery on review completion

Example local call:

```bash
CONFIG_STUDIO_URL=http://127.0.0.1:8000 \
CONFIG_STUDIO_API_KEY=dev-engine-key \
./examples/pipeline-review.sh ./apps/engine/tests/fixtures/cisco_ios_bad.conf critical
```

See `examples/` for:
- `github-actions-config-review.yml`
- `gitlab-ci.yml`
- `Jenkinsfile`
- `pipeline-review.sh`

## ITSM export endpoint

Config Studio now exposes a direct report-export endpoint for ServiceNow and Jira Cloud:

```bash
POST /api/export/review
```

It renders the same structured review artifact used by JSON/PDF report generation, then attaches those artifacts to a ServiceNow change record or Jira issue and optionally posts a summary comment/work note.

Highlights:
- ServiceNow change record attachment via `/api/now/attachment/file`
- ServiceNow work-note / short-description update via `/api/now/table/...`
- Jira Cloud issue attachment via `/rest/api/3/issue/{key}/attachments`
- Jira comment creation via `/rest/api/3/issue/{key}/comment`
- same review payload reused for both export and normal report generation

Example Jira export call:

```bash
CONFIG_STUDIO_URL=http://127.0.0.1:8000 \
CONFIG_STUDIO_API_KEY=dev-engine-key \
JIRA_BASE_URL=https://your-org.atlassian.net \
JIRA_TOKEN=... \
./examples/jira-export.sh ./apps/engine/tests/fixtures/cisco_ios_bad.conf NET-123
```

Example ServiceNow export call:

```bash
CONFIG_STUDIO_URL=http://127.0.0.1:8000 \
CONFIG_STUDIO_API_KEY=dev-engine-key \
SERVICENOW_INSTANCE_URL=https://example.service-now.com \
SERVICENOW_USERNAME=api-user \
SERVICENOW_PASSWORD=api-pass \
./examples/servicenow-export.sh ./apps/engine/tests/fixtures/cisco_ios_bad.conf 0123456789abcdef0123456789abcdef
```

See `examples/` for:
- `jira-export.sh`
- `servicenow-export.sh`
