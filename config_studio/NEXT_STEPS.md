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

### 1. Reporting flow
Requirements:
- REQ-3.4.1 JSON + PDF output from same underlying data
- REQ-3.4.2 report header
- REQ-3.4.3 report body sections
- REQ-3.4.5 self-contained report

Target:
- add a real report model in the engine
- produce downloadable JSON report artifact from analyzed config
- shape output for QA/compliance readability, not just raw API data

### 2. Template flow
Requirements:
- REQ-3.2.1 guided template usage with day-one default review
- REQ-3.2.3 template versioning
- REQ-3.2.4 starter templates

Target:
- load starter templates from engine defaults instead of hardcoded frontend copies
- show applied template in UI/report

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
