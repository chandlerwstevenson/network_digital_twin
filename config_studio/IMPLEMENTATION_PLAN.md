# Config Studio — Recovery & Implementation Plan

## Current State

This repo is not a finished app. It is an early product skeleton with:

- a partially implemented Python analysis engine
- an Electron desktop wrapper
- shared domain types
- a Supabase schema draft
- an empty `apps/web/` directory
- no production-ready end-to-end user flow

The biggest blocker is simple: **the primary web UI is missing**.

## What absolutely needs to be done

### 1) Recover or build the web app

`apps/web/` is empty, but the rest of the repo assumes it exists.

Needed MVP UI surfaces:
- review workspace / landing page
- config paste area
- findings list with severity filters
- quick-pass toggle
- snippet mode toggle / auto-detection display
- compare running vs startup view
- natural-language query panel
- dark mode
- basic settings / template selection

### 2) Stabilize the engine

Highest-leverage fixes:
- enforce API key auth for internal engine calls when configured
- fix NL query fallback behavior so it degrades cleanly
- fix remediation enrichment logic so placeholder commands can actually be normalized
- add smoke tests around `/analyze`, `/compare`, `/query`
- improve line attribution and noisy heuristics over time

### 3) Wire persistence

The schema exists, but the app does not appear connected to it.

Need:
- save review metadata
- save findings
- save report metadata
- save query history
- load starter templates
- org/user bootstrap flow

### 4) Add auth + app shell

Need:
- Supabase auth integration
- org creation / membership bootstrap
- role-aware navigation
- empty states that still provide day-one value

### 5) Build reporting

Need:
- JSON report generation first
- PDF rendering second
- report metadata + download flow

### 6) Desktop packaging only after web is real

Electron currently depends on built static renderer output.
That path is premature until the UI exists.

## Recommended execution order

### Phase 1 — unblock the product
1. Build `apps/web` MVP
2. Fix engine reliability issues
3. Add local dev instructions
4. Add smoke tests

### Phase 2 — make it usable
1. Supabase auth + persistence
2. Review history list
3. Starter templates loading
4. JSON export

### Phase 3 — make it credible
1. PDF reports
2. Better lint quality
3. Template authoring UI
4. Desktop packaging hardening

## Work completed in this pass

- Confirmed `apps/web/` is empty and is the main product gap
- Identified engine issues that block reliability
- Prioritized work toward shipping an MVP instead of polishing dead ends

## Immediate next coding tasks

1. Fix backend reliability issues
2. Add backend tests
3. Create a real `apps/web` MVP scaffold
4. Connect the web app to engine endpoints

## Notes

Do not spend time on advanced roadmap items yet (peer review, cross-config correlation, CI integrations, full org analytics) until the basic single-user config review flow exists end to end.
