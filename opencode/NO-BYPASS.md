# opencode: pinned version, patch, and the no-bypass proof

## Pinned version
- **opencode-ai 1.19.5** (npm, published 2026-10-28T06:17Z): the newest release before the base commit's date.
- Image `cleanroom/opencode:1.19.5`, built from `Dockerfile`. Adapted from harness_k3's `Dockerfile.opencode-base`, copied here;
  harness_k3 itself was not modified.
- Source audited at tag v1.19.5 (`build/opencode-v1.19.5.tar.gz`, sha256 `7d2ac43b…5e7a`, from github.com/anomalyco/opencode).

## Audit: where opencode talks to the network (packages/opencode/src, v1.19.5)
| Path | What | How it is handled |
|---|---|---|
| provider (AI SDK) | the model API (api.anthropic.com) | through the proxy, pass-through, logged with token usage |
| `tool/webfetch` | arbitrary URLs | through the proxy, filtered |
| `tool/mcp-websearch.ts` | `https://mcp.exa.ai/mcp` (or search.parallel.ai) | enabled with `OPENCODE_ENABLE_EXA=1`; through the proxy, results filtered |
| `core/models-dev.ts` | `https://models.opencode.ai/api.json` | `OPENCODE_DISABLE_MODELS_FETCH=1`; Haiku 5.5 declared in `opencode.json` |
| `cli/upgrade`, installation | update checks | `OPENCODE_DISABLE_AUTOUPDATE=1` + `"autoupdate": false` |
| share | opencode.ai share links | `OPENCODE_DISABLE_SHARE=1` + `"share": "disabled"` |
| plugins | default plugins from npm | `OPENCODE_DISABLE_DEFAULT_PLUGINS=1` |
| config dir | background `npm install @opencode-ai/plugin` into ~/.config/opencode | still happens; goes through the proxy to registry.npmjs.org (seen in the log); harmless |
| `lsp/server.ts` | language-server downloads (GitHub releases, etc.) | `OPENCODE_DISABLE_LSP_DOWNLOAD=1` |
| MCP | none configured (`"mcp": {}`) | none |
| skills / Claude Code import | ~/.claude, external skills | `OPENCODE_DISABLE_EXTERNAL_SKILLS=1`, `OPENCODE_DISABLE_CLAUDE_CODE=1` |
| bash tool | curl / pip / git / npm run by the agent | `HTTP(S)_PROXY` set; anything that ignores it hits the firewall |

opencode has no proxy code of its own. It relies on the Bun runtime, whose fetch honours `HTTP(S)_PROXY` and
`NODE_EXTRA_CA_CERTS`. The proxy log confirms this: the model calls, webfetch and websearch all appear in it.

**Patch: config and env only, no source patch.** No source patch is needed because the guarantee comes from the network,
not from opencode's goodwill:
- the container sits only on `cleanroom-int`, a Docker network with `internal: true` (subnet 10.88.0.0/24);
- `entrypoint.sh` sets the OUTPUT policy to DROP. It allows only `lo` and tcp 10.88.0.1:8080 (the proxy), REJECTs the
  rest, and drops all IPv6;
- it then runs the agent with an empty capability bounding set and `no-new-privs`, so nothing inside can undo the firewall.

The firewall matters because the internal network alone is **not** enough. From it, the host's bridge IP answers on about 30
host services: ssh, and HTTP services that return 404/401/200 (`proxy/logs` scan, 2026-11-04). One of them could act as an
un-filtered fetcher. The container's firewall refuses them all (probes ":22" and ":47102" below).

## The proof — `nobypass_test.sh`, run 2026-11-04
The same 18 probes run against the same image, once with the proxy up and once with it down.
- **Up:** `nobypass-up.out`, 18/18 PASS.
- **Down:** `nobypass-down.out`, 18/18 PASS.

| Probe | proxy up | proxy down |
|---|---|---|
| agent runs `iptables -F` | fails (no CAP_NET_ADMIN) | fails |
| CapEff == 0 | yes | yes |
| curl --noproxy https://example.com | fails (no DNS) | fails |
| curl --noproxy https://1.1.1.1 | fails (REJECT) | fails |
| host bridge :22, :47102 | fail (REJECT) | fail |
| python urllib, no proxy | fails | fails |
| external DNS | fails | fails |
| IPv6 egress | fails | fails |
| curl via proxy, neutral NVIDIA doc | 200 | fails |
| curl via proxy, PR #64893 | 403 | fails |
| git clone vllm via proxy | 403 | fails |
| pip download humming-kernels | ok | fails |
| npm view | ok | fails (timeout) |
| opencode model call (Haiku 5.5) | PONG | ECONNREFUSED |
| opencode webfetch | ok | fails |
| opencode websearch (Exa) | ok | fails |
| opencode webfetch of #64893 | agent reports BLOCKED (403) | fails |

Hosts the proxy saw during the up run (`proxy/logs/nobypass.jsonl`): api.anthropic.com (11, pass-through), docs.nvidia.com,
mcp.exa.ai, github.com (3 blocks), pypi.org, files.pythonhosted.org, registry.npmjs.org. There was no telemetry, update or
models.dev traffic.

Cost of the proof: 11 Haiku 5.5 calls, ~1–9k tokens each, mostly cache reads (`proxy/logs/anthropic_usage.jsonl`).
That is well under $0.01.

## Not covered
- A GPU container (nvidia runtime) for compile/unit tests has not been tested yet; it gets the same entrypoint.
- DNS tunnelling: Docker's embedded DNS answers SERVFAIL for external names on the internal network, so I see no path.
  I did not test it adversarially.
- Exa search results reach the agent only after filtering. The websearch request itself (the agent's query) leaves through
  the proxy and is logged; queries are outbound data, not a leak into the agent.
