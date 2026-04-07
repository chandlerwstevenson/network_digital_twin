#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "usage: $0 <config-file> <webhook-url>" >&2
  exit 64
fi

CONFIG_FILE="$1"
WEBHOOK_URL="$2"
CONFIG_STUDIO_URL="${CONFIG_STUDIO_URL:-http://127.0.0.1:8000}"
CONFIG_STUDIO_API_KEY="${CONFIG_STUDIO_API_KEY:-dev-engine-key}"
WEBHOOK_HEADER_NAME="${WEBHOOK_HEADER_NAME:-}"
WEBHOOK_HEADER_VALUE="${WEBHOOK_HEADER_VALUE:-}"

python3 - "$CONFIG_FILE" "$WEBHOOK_URL" <<'PY'
import json
import os
import pathlib
import sys
import urllib.request

config_path = pathlib.Path(sys.argv[1])
webhook_url = sys.argv[2]
config_text = config_path.read_text(encoding='utf-8')
headers = {}
if os.environ.get('WEBHOOK_HEADER_NAME'):
    headers[os.environ['WEBHOOK_HEADER_NAME']] = os.environ.get('WEBHOOK_HEADER_VALUE', '')

payload = {
    'config_text': config_text,
    'engineer_name': 'Local webhook export script',
    'target': 'webhook',
    'webhook': {
        'url': webhook_url,
        'headers': headers,
        'include_review_payload': True,
        'embed_artifacts': False,
    },
    'include_pdf': True,
    'include_json': True,
    'export_comment': 'Automated Config Studio export to generic ITSM webhook.',
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
