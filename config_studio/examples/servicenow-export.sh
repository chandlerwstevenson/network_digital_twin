#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "usage: $0 <config-file> <change-sys-id>" >&2
  exit 64
fi

CONFIG_FILE="$1"
CHANGE_SYS_ID="$2"
CONFIG_STUDIO_URL="${CONFIG_STUDIO_URL:-http://127.0.0.1:8000}"
CONFIG_STUDIO_API_KEY="${CONFIG_STUDIO_API_KEY:-dev-engine-key}"
SERVICENOW_INSTANCE_URL="${SERVICENOW_INSTANCE_URL:?set SERVICENOW_INSTANCE_URL}"
SERVICENOW_USERNAME="${SERVICENOW_USERNAME:?set SERVICENOW_USERNAME}"
SERVICENOW_PASSWORD="${SERVICENOW_PASSWORD:?set SERVICENOW_PASSWORD}"

python3 - "$CONFIG_FILE" "$CHANGE_SYS_ID" <<'PY'
import json
import pathlib
import sys
import urllib.request
import os

config_path = pathlib.Path(sys.argv[1])
record_sys_id = sys.argv[2]
config_text = config_path.read_text(encoding='utf-8')

payload = {
    'config_text': config_text,
    'engineer_name': 'Local ServiceNow export script',
    'target': 'servicenow',
    'auth': {
        'auth_type': 'basic',
        'username': os.environ['SERVICENOW_USERNAME'],
        'password': os.environ['SERVICENOW_PASSWORD'],
    },
    'service_now': {
        'instance_url': os.environ['SERVICENOW_INSTANCE_URL'],
        'table_name': 'change_request',
        'record_sys_id': record_sys_id,
    },
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
