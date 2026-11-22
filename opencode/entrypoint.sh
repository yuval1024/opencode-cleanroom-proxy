#!/usr/bin/env bash
# 1) Lock egress to the filtering proxy (needs CAP_NET_ADMIN, which step 3 drops for good).
# 2) Write opencode's Anthropic credential from the read-only secret mount (never printed).
# 3) Exec the command with no capabilities and no-new-privs, so nothing in the container can undo step 1.
set -euo pipefail
PROXY_HOST=${PROXY_HOST:-10.88.0.1}; PROXY_PORT=${PROXY_PORT:-8080}
if [[ "${SKIP_FIREWALL:-0}" != "1" ]]; then
  iptables -F OUTPUT; iptables -P OUTPUT DROP
  iptables -A OUTPUT -o lo -j ACCEPT
  iptables -A OUTPUT -p tcp -d "$PROXY_HOST" --dport "$PROXY_PORT" -j ACCEPT
  iptables -A OUTPUT -j REJECT
  ip6tables -F OUTPUT 2>/dev/null || true; ip6tables -P OUTPUT DROP 2>/dev/null || true
  ip6tables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
fi
export HTTP_PROXY="http://$PROXY_HOST:$PROXY_PORT" HTTPS_PROXY="http://$PROXY_HOST:$PROXY_PORT"
export http_proxy="$HTTP_PROXY" https_proxy="$HTTPS_PROXY" NO_PROXY="localhost,127.0.0.1" no_proxy="localhost,127.0.0.1"
KEY_FILE=${ANTHROPIC_KEY_FILE:-/run/secrets/anthropic_key}
if [[ -r "$KEY_FILE" ]]; then
  K=$(grep -oE 'sk-ant-[A-Za-z0-9_-]+' "$KEY_FILE" | head -1 || true)
  if [[ -n "$K" ]]; then
    mkdir -p /root/.local/share/opencode
    jq -n --arg k "$K" '{anthropic: {type: "api", key: $k}}' > /root/.local/share/opencode/auth.json
    chmod 600 /root/.local/share/opencode/auth.json
  fi
  unset K
fi
unset ANTHROPIC_API_KEY OPENROUTER_API_KEY || true
exec setpriv --no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all -- "$@"
