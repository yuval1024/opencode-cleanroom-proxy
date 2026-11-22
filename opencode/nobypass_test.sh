#!/usr/bin/env bash
# No-bypass proof for the agent container. Usage: nobypass_test.sh <proxy-state-label>
# Runs the same probes with the proxy up and with it down. Every probe prints PASS/FAIL against the
# expectation for that state. Model calls are tiny (opencode run, one short prompt each).
set -u
LABEL=${1:-up}; HERE=$(cd "$(dirname "$0")" && pwd); R=$(cd "$HERE/.." && pwd)
IMG=cleanroom/opencode:1.19.5
RUN="docker run --rm --network cleanroom-int --cap-add NET_ADMIN --security-opt no-new-privileges \
  -v /run/secrets/anthropic-api-key:/run/secrets/anthropic_key:ro -e RUN_LABEL=$LABEL $IMG"
expect_up=$([ "$LABEL" = up ] && echo 1 || echo 0)
probe() { # name, expect(ok|fail), command...
  local name=$1 exp=$2; shift 2
  out=$($RUN bash -lc "$*" 2>&1); rc=$?
  last=$(echo "$out" | tail -1 | cut -c1-140)
  if { [ "$exp" = ok ] && [ $rc -eq 0 ]; } || { [ "$exp" = fail ] && [ $rc -ne 0 ]; }; then v=PASS; else v=FAIL; fi
  echo "$v [$LABEL] $name (expect $exp, rc=$rc): $last"
}
UP=$([ $expect_up = 1 ] && echo ok || echo fail)
# --- container lock-down (same in both states) ---
probe "iptables cannot be changed by the agent" fail 'iptables -F OUTPUT'
probe "no capabilities left" ok '[ "$(grep CapEff /proc/self/status | awk "{print \$2}")" = 0000000000000000 ]'
probe "direct HTTPS ignoring proxy env" fail 'curl -sS --noproxy "*" --max-time 8 -o /dev/null https://example.com'
probe "direct to an IP (1.1.1.1:443)" fail 'curl -sS --noproxy "*" --max-time 8 -o /dev/null https://1.1.1.1'
probe "host bridge service :22" fail 'curl -sS --noproxy "*" --max-time 5 -o /dev/null http://10.88.0.1:22'
probe "host bridge service :47102" fail 'curl -sS --noproxy "*" --max-time 5 -o /dev/null http://10.88.0.1:47102'
probe "python urllib without proxy" fail 'python3 -c "import urllib.request as u; u.build_opener(u.ProxyHandler({})).open(\"https://pypi.org\", timeout=8)"'
probe "DNS for external names" fail 'getent hosts example.com'
probe "IPv6 egress" fail 'curl -sS -6 --noproxy "*" --max-time 5 -o /dev/null https://[2606:4700:4700::1111]'
# --- through the proxy ---
probe "curl via proxy: neutral doc" $UP 'curl -fsS --max-time 60 -o /dev/null https://docs.nvidia.com/cuda/hopper-tuning-guide/index.html'
probe "curl via proxy: fix PR (must be 403)" fail 'curl -fsS --max-time 60 -o /dev/null https://github.com/vllm-project/vllm/pull/64893'
probe "git clone vllm via proxy (blocked)" fail 'timeout 60 git clone --depth 1 https://github.com/vllm-project/vllm.git /tmp/v'
probe "pip download via proxy" $UP 'timeout 120 pip download --no-deps -q -d /tmp/p humming-kernels==0.1.19 --break-system-packages 2>&1 || timeout 120 pip download --no-deps -q -d /tmp/p humming-kernels==0.1.19'
probe "npm registry via proxy" $UP 'timeout 60 npm view left-pad version'
# --- opencode tools (each is one short model call through the proxy) ---
OC='cd /tmp && timeout 300 opencode run --print-logs=false'
probe "opencode: model call (Anthropic via proxy)" $UP "$OC 'Reply with exactly: PONG' 2>&1 | tee /dev/stderr | grep -q PONG"
probe "opencode: webfetch tool" $UP "$OC 'Use the webfetch tool to fetch https://docs.nvidia.com/cuda/hopper-tuning-guide/index.html and reply with only the first heading you see, then the word DONE.' 2>&1 | tee /dev/stderr | grep -q DONE"
probe "opencode: websearch tool" $UP "$OC 'Use the websearch tool to search for: CUDA thread block clusters. Reply with one result title, then the word DONE.' 2>&1 | tee /dev/stderr | grep -q DONE"
probe "opencode: webfetch of the fix PR is refused" $UP "$OC 'Use the webfetch tool to fetch https://github.com/vllm-project/vllm/pull/64893 . If the fetch fails or returns 403 reply BLOCKED, otherwise reply OPEN.' 2>&1 | tee /dev/stderr | grep -q BLOCKED"
