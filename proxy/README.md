# proxy/: the clean-room filter

mitmproxy 11.0.2 addon (`addon.py`) on the host, listening only on 10.88.0.1:8080, which is the bridge IP of the Docker
network `cleanroom-int` (internal, 10.88.0.0/24). The agent container's only allowed egress is this socket (see
`../opencode/NO-BYPASS.md`). Start and stop it with `proxyctl.sh start <tag> [ENV=…]` / `proxyctl.sh stop`.

## Pipeline, per request
1. **URL rules** (`rules.url_verdict`, deterministic) run before any upstream connection:
   - **block (403)** with the neutral text *"This resource is not available from this environment's network filter"*;
   - **pass** (api.anthropic.com only: forwarded direct, never inspected, token usage logged to `logs/anthropic_usage.jsonl`);
   - **binary** (package files, other repos' git packs, images: forwarded and logged as unclassified);
   - **filter**.
2. **Upstream:** Webshare (a random proxy from the 1,000-proxy list, with dead ones benched for 5 min) for every host except
   Anthropic. Measured egress IPs are Webshare's, never ours.
3. **Filter** (responses):
   - JSON result lists are judged item by item; a leaky item becomes `{"redacted_by_network_filter": true}`.
   - HTML and text are split into ~4,000-char chunks; a leaky chunk is replaced with a redaction marker, and the HTML is
     then served as text/markdown.
   - If ≥ 50% of the text is leaky, the whole response is blocked.
   - Structured non-list content (JSON objects, JS) is never cut: any leak blocks it.
   - "Leaky" means a deterministic content rule hit (`rules.content_hits`), else Jev p ≥ 0.20.
   - If Jev is unavailable the filter fails closed (`JEV_FAIL=block`).
4. **Logs:**
   - one line per flow in `decisions.jsonl` (url, verdict, rule, per-chunk/item hits and Jev p);
   - the removed text in `logs/removed/<flow>.json` (judge side only, never mounted into the agent).

## Haiku 5.5 judge on top of Jev (`haiku_judge.py`)
For every chunk/item not caught by a rule, Jev and Haiku 5.5 (effort low, JSON schema output, direct to Anthropic with the
API key) run in parallel. The verdict:
- Haiku says leak → leak;
- Jev ≥ 0.60 overrides Haiku's "clean";
- Haiku's "clean" overrides a weak Jev positive (0.20–0.60);
- if Haiku is unavailable or over its $1/day cap, Jev ≥ 0.20 decides.

N=10: Haiku catches 5/5 leaks, **including #64892's body that Jev scored 0.14**. It has 1/5 false positives (#62958,
DSpark-on-Hopper, pre-base). Two items (C3, C5) were used to tune the prompt, so N=10 is not held-out for Haiku.

Extended set with rules + Jev + Haiku: 29/34. The misses are the same 5 content-free replies. The mixed page is 1/1 and 0/5.

**Every request and result is saved:**
- Jev: `logs/jev_requests.jsonl` (full request body including the state text, raw response, usage, latency, cache hits);
- Haiku: `logs/haiku_judge.jsonl` (document, raw response text, verdict, tokens, cost).

These are the training data for a future filter on top of Jev.

**Package indexes** (PyPI simple/JSON, npm, download.pytorch.org, astral) get verdict `index`: deterministic rules only, no
model calls. During cycle 1 they had cost ≈ $0.11 of Jev in minutes.

## Real searches, raw vs what the agent sees (`tests/real_search_test.py`)
The test sends opencode's own websearch request (Exa MCP `web_search_exa`, 8 results) for 6 leak-seeking and 2 neutral
queries, two ways:
- **raw:** from the host through Webshare only;
- **filtered:** through the agent's proxy.

Every result is scored by the deterministic rules and an evaluator Haiku that has its own cache.

| Run | Leaky results raw | Leaky reaching the agent | Neutral queries |
|---|---|---|---|
| exa-1: 4k-char chunking of the SSE body | 12 | 1, and the SSE JSON was broken by redaction (3 queries got a 403) | FlashMLA: 8 → 1 (collateral) |
| exa-2: per-result MCP handling (valid JSON-RPC kept) | 11 | 3 | 8/8 and 8/8 untouched |
| exa-3: + rule "links to post-base vLLM work" (commit not an ancestor, PR ≥ 64883) | 14 | **1**, which is not a leak (below) | 8/8 and 8/8 untouched |

- **The remaining item** is NVIDIA Dynamo's DeepSeek-V4.1-Flash recipe: a stock H200 deployment (CUTLASS MoE, EPLB,
  DSpark), with no specialized-decode port. The evaluator flagged it. The filter's own Haiku called the same text a leak in
  one call and clean in another. Haiku is **non-deterministic on borderline text**; this is why it is combined with the
  rules and Jev rather than used alone.
- **Raw leak counts vary between runs** (11–14) because the search results themselves change.

## Deterministic rules (`rules.py`)
- **URLs:**
  - vLLM PRs/issues #64893, #64892, #63921, and **any number ≥ 64883** (opened after the base);
  - `compare/`, branches/tags/commits listings;
  - any vLLM ref that is not an ancestor of the base (24,279 ancestor shas in `rules_data/`), so `main` is blocked;
  - git smart-HTTP for vllm-project/vllm, and anything under github.com/mgoin;
  - the tweet id and SemiAnalysis/mgoin on X mirrors;
  - vllm wheels on PyPI and wheels.vllm.ai.
- **Content:**
  - fix PR numbers, branch names and shas, and the tweet id;
  - the "10,000 LoC … Hopper" and "Hopper … 38%" claims, including CJK numerals;
  - "ultra-fused Hopper", and `latency_specialized` within 600 chars of a Hopper term;
  - "specialized decode" + Hopper + DeepSeek-V4.1, and mgoin + Hopper + DeepSeek + decode;
  - `specialized_decode/hopper` paths;
  - links to post-base vLLM work (`vllm-project/vllm@<sha>` or `/commit/<sha>` not an ancestor of the base, `/pull|issues/N`
    with N ≥ 64883).
- **False positives on the base tree itself:** 0 / 28,257 chunks of the base checkout's .py/.md/.yaml/.cu
  (`tests/fp_on_base_repo.out`).

## Test results (2026-11-04)
Jev runs via treg→OpenRouter (`typesafe/jev-1.13`) at threshold **0.20**, which was lowered from 0.30 after the neutral run:
no neutral chunk scored above 0.10.

| Test | Deterministic only | Rules + Jev (production) |
|---|---|---|
| unit tests `tests/test_rules.py` | 62/62 | n/a |
| leak URLs → 403 (PR page, .diff, patch-diff, API, files, #64892, mgoin branch, compare, tweet, #63921) | **10/10** | **10/10** |
| leak searches (DuckDuckGo ×2, GitHub search API, Exa MCP) → no leak left | **4/4** | **4/4** (Exa: 2 chunks redacted at p 0.41/0.42) |
| neutral pages (30; one GitHub 429) | 29 fetched, **0 FP** | 29 fetched, **0 FP**; 304 chunks/items scored, max neutral p = 0.10 |
| ↳ the one redaction on #61868 | GitHub's cross-reference line to #64893 (a true positive) | same |
| extended labelled set, item level | 13/34 → **24/34** after the three thread rules (mgoin~Hopper, agent swarm~kernels, mgoin~10k) | **29/34** |
| ↳ SemiAnalysis thread replies | 7/23 → 18/23 | 18/23 (the 5 misses are 46–274-char replies with no technical term; Jev p ≤ 0.06) |
| ↳ Chinese paraphrase 2116679257145414070 | 1/1 | 1/1 |
| ↳ mechanism reply 2116667541720543554 | 1/1 | 1/1 |
| ↳ #64893 / #64892 body chunks | 2/5 | **5/5** |
| ↳ synthetic code-only leaks | 3/5 | **5/5** |
| mixed page (neutral Hopper tuning guide + 1 leaking paragraph), chunk level | 1/1 redacted, 0/5 clean touched | 1/1, 0/5 |
| base tree (28,257 chunks) deterministic FP | 1 (DeepGEMM README: "mgoin" near "H100") | n/a |
| Jev N=10 (`JEV.md`) | — | at 0.20: recall 4/5, FP 0/5 |

Jev spend for all of the above: **$0.0245** (327 calls) out of the budget cap. The same ledger
(`logs/jev_cache.sqlite`) is used by the live proxy.

## Not covered
- Search results the agent reads through opencode's websearch go to Exa via the proxy; queries are logged, not filtered.
- Binary content (wheels, tarballs, git packs of other repos) is not inspected.
