#!/usr/bin/env bash
# Start the filtering proxy. Usage: run_proxy.sh <listen-host> <port> [extra mitmdump args]
# Env passes through to addon.py (JEV_MODE, JEV_CAP_USD, RUN_TAG, DECISIONS_LOG, ...).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
HOST=${1:-127.0.0.1}; PORT=${2:-18080}; shift 2 || true
exec mitmdump --set confdir="$HERE/certs" --set connection_strategy=lazy --set stream_large_bodies=50m \
  --set block_global=false --listen-host "$HOST" --listen-port "$PORT" -q -s "$HERE/addon.py" "$@"
