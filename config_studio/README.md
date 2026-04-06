# Optimesh Config Studio

Config Studio is a network configuration review product prototype.

Current repo contents:
- `apps/engine` — FastAPI analysis engine for config review
- `apps/desktop` — Electron shell that embeds the engine and a static renderer
- `apps/web` — working static frontend for review, query, batch review, template authoring, compare, and operator workflows
- `packages/shared` — shared TypeScript domain types
- `supabase/` — schema and backend data model draft
- `examples/` — CI/CD integration examples for GitHub Actions, GitLab CI, Jenkins, and a local shell gate

## Status

This repository is now a **working end-to-end prototype**, not just an engine stub.

The current implementation covers the day-one web flow plus a pipeline-oriented REST gate for pre-merge / pre-deploy review. See `REQUIREMENT.txt` for product targets and `NEXT_STEPS.md` for the current structured work loop.

## Engine development

### Requirements
- Python 3.11+

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

## Desktop app

The desktop app expects a built static renderer under the web app output path.
At the moment, desktop packaging is incomplete because `apps/web` is not implemented.

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
