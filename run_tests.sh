#!/usr/bin/env bash
#
# run_tests.sh — the full test suite. No network, no real cluster, no credentials.
#
# Everything runs against tools/mock_es_server.py on a loopback port, so this is
# safe to run anywhere, including CI.
#
#   ./run_tests.sh          # quiet
#   ./run_tests.sh -v       # per-test names
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

echo "==> Python: $(python3 --version)"
python3 -c "import requests" 2>/dev/null || {
    echo "!!  'requests' is not installed. Run: pip install -r requirements.txt" >&2
    exit 1
}

echo "==> Unit and integration tests"
python3 -m unittest discover -s tests -t . "$@"

echo
echo "==> Config validation: the shipped inventory parses"
python3 ccs_health_check.py --clusters es_clusters.json --show-config >/dev/null
echo "    OK"

echo "==> Template rendering: state store"
python3 setup/setup_state_store.py --clusters es_clusters.json --dry-run >/dev/null
echo "    OK"

echo "==> Template rendering: alerting rules"
python3 alerting/setup_alerting.py --kibana-url https://kibana.invalid \
    --probe-interval-minutes 5 --connector-id dry --to dry@example.gov \
    --include-info --dry-run >/dev/null
echo "    OK"

echo
echo "All checks passed."
