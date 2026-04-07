#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "usage: $0 <config-file> <jira-issue-key>" >&2
  exit 64
fi

CONFIG_FILE="$1"
JIRA_ISSUE_KEY="$2"
CONFIG_STUDIO_URL="${CONFIG_STUDIO_URL:-http://127.0.0.1:8000}"
CONFIG_STUDIO_API_KEY="${CONFIG_STUDIO_API_KEY:-dev-engine-key}"
JIRA_BASE_URL="${JIRA_BASE_URL:?set JIRA_BASE_URL}"
JIRA_TOKEN="${JIRA_TOKEN:?set JIRA_TOKEN}"

python3 - "$CONFIG_FILE" "$JIRA_ISSUE_KEY" <<'PY'
import json
import pathlib
import sys
import urllib.request
import os

config_path = pathlib.Path(sys.argv[1])
issue_key = sys.argv[2]
config_text = config_path.read_text(encoding='utf-8')

payload = {
    'config_text': config_text,
    'engineer_name': 'Local Jira export script',
    'target': 'jira',
    'auth': {'auth_type': 'bearer', 'token': os.environ['JIRA_TOKEN']},
    'jira': {'base_url': os.environ['JIRA_BASE_URL'], 'issue_key': issue_key},
    'include_pdf': True,
    'include_json': True,
    'export_comment': 'Automated Config Studio export from local workflow.',
}
request = urllib.request.Request(
    f"{os.environ['CONFIG_STUDIO_URL'].rstrip('/')}/api/export/review",
    data=json.dumps(payload).encode('utf-8'),
    headers={
        'Content-Type': 'application/json',
        'x-api-key': os.environ['CONFIG_STUDIO_API_KEY'],
    },
    method='POST',
)
with urllib.request.urlopen(request, timeout=90) as response:
    body = json.loads(response.read().decode('utf-8'))
print(json.dumps(body, indent=2))
PY
