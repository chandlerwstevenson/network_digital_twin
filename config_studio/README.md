# Optimesh Config Studio

Config Studio is a network configuration review product prototype.

Current repo contents:
- `apps/engine` — FastAPI analysis engine for config review
- `apps/desktop` — Electron shell that embeds the engine and a static renderer
- `apps/web` — intended primary UI surface (**currently missing / not implemented**)
- `packages/shared` — shared TypeScript domain types
- `supabase/` — schema and backend data model draft

## Status

This repository is **not yet a complete application**.

The engine exists and can be developed locally, but the main web frontend is not present in the repo right now. See `IMPLEMENTATION_PLAN.md` for the recovery and execution plan.

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

## Priority

The next critical task is to build or restore `apps/web` so the product has a usable end-to-end flow.
