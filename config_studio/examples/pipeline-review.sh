#!/usr/bin/env bash
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "usage: $0 <config-file> [fail-on-severity]" >&2
  exit 64
fi

CONFIG_FILE="$1"
FAIL_ON_SEVERITY="${2:-critical}"
CONFIG_STUDIO_URL="${CONFIG_STUDIO_URL:-http://127.0.0.1:8000}"
CONFIG_STUDIO_API_KEY="${CONFIG_STUDIO_API_KEY:-dev-engine-key}"

python3 - "$CONFIG_FILE" "$FAIL_ON_SEVERITY" <<'PY'
import json
import pathlib
import sys
import urllib.request

config_path = pathlib.Path(sys.argv[1])
fail_on_severity = sys.argv[2]
config_text = config_path.read_text(encoding='utf-8')

payload = {
    'config_text': config_text,
    'engineer_name': 'Local pipeline script',
    'fail_on_severity': fail_on_severity,
    'include_review': False,
}
request = urllib.request.Request(
    f"{__import__('os').environ['CONFIG_STUDIO_URL'].rstrip('/')}/api/pipeline/review",
    data=json.dumps(payload).encode('utf-8'),
    headers={
        'Content-Type': 'application/json',
        'x-api-key': __import__('os').environ['CONFIG_STUDIO_API_KEY'],
    },
    method='POST',
)
with urllib.request.urlopen(request, timeout=60) as response:
    body = json.loads(response.read().decode('utf-8'))
print(json.dumps(body, indent=2))
raise SystemExit(1 if body.get('should_block') else 0)
PY
