#!/usr/bin/env bash
# proxyctl.sh start <tag> [ENV=...] | stop | status   — the agent-facing proxy on 10.88.0.1:8080
HERE=$(cd "$(dirname "$0")" && pwd); PID=$HERE/logs/proxy.pid
listener() { ss -ltnp 2>/dev/null | grep '10.88.0.1:8080 ' | grep -oP 'pid=\K[0-9]+' | head -1; }
case "${1:-status}" in
  start) TAG=${2:-manual}; shift 2 || true
         L=$(listener); [ -n "$L" ] && { echo "port in use by pid $L; run stop first"; exit 1; }
         env RUN_TAG="$TAG" DECISIONS_LOG="${DECISIONS_LOG:-$HERE/decisions.jsonl}" "$@" \
           nohup "$HERE/run_proxy.sh" 10.88.0.1 8080 > "$HERE/logs/proxy-$TAG.out" 2>&1 &
         sleep 3; L=$(listener)
         if [ -n "$L" ]; then echo "$L" > "$PID"; echo "started pid $L tag=$TAG"; else echo "FAILED to start:"; tail -3 "$HERE/logs/proxy-$TAG.out"; exit 1; fi ;;
  stop)  for P in $(listener) $(cat "$PID" 2>/dev/null); do kill "$P" 2>/dev/null; done
         for i in $(seq 1 10); do [ -z "$(listener)" ] && break; sleep 1; done
         L=$(listener); [ -n "$L" ] && { kill -9 "$L"; sleep 1; }
         rm -f "$PID"; [ -z "$(listener)" ] && echo stopped || echo "STILL RUNNING" ;;
  status) L=$(listener); [ -n "$L" ] && echo "running pid $L" || echo "not running" ;;
esac
