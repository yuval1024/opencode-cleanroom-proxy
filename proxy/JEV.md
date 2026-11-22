# Jev (TypeSafe) — API, N=10 trial, cost

## API
- Native: `POST https://api.typesafe.ai/v1/systemone`, `Authorization: Bearer <key>`, body `{model, state, questions}`;
  `noul` question → `answers.<id>.noul` in [0,1]; `usage.input_tokens` billed at $0.042/M (jev-1.13.0), output free.
  Source: docs.typesafe.ai/api, promptfoo and pipecat integration docs (fetched 2026-11-04).
- **Our key `/run/secrets/jev-api-key` is rejected**: 401 `authentication_error` on `/v1/systemone` and `/v1/models`
  (51-char key, `JEV_API_KEY=` line parsed cleanly, Bearer scheme as documented). The 10 failed calls billed 0 tokens
  (`jev_trial/results-direct-401.*`). → operator question.
- **Working route:** Jev through OpenRouter (`/api/alpha/decisions`, model `typesafe/jev-1.13`, served as
  `typesafe/jev-1.13-20260917`), called with the treg CLI (`treg call openrouter.ai-judge.decide`), billed to the
  treg prepaid balance (cost = reply `usage.cost`). Implemented as `Jev(..., backend="treg")` in `jev.py`.

## Question
One `noul` question (`jev.QUESTION`): TRUE if the text reveals the Hopper/SM90 port of the DeepSeek-V4.1 specialized decode
(PRs #64893/#64892, mgoin's branches/posts, the SemiAnalysis post, any other Hopper port); FALSE for general CUDA/PTX/
CUTLASS/vLLM/DeepSeek material and the GB300 executor itself. State = `# Decision context\n\n<text>…</text>`, HTML-escaped,
≤ 9,000 chars.

## N=10 trial (2026-11-04) — `jev_trial/items.jsonl`, `results.json`, `ledger.sqlite`
| id | label | p_leak | input tok | item |
|---|---|---|---|---|
| L1 | leak | 0.69 | 1026 | #64893 body, Overview |
| L2 | leak | 0.55 | 903 | #64893 design paragraph without PR numbers |
| L3 | leak | 0.75 | 1020 | GitHub search item for #64893 |
| L4 | leak | 0.66 | 711 | the SemiAnalysis tweet text |
| L5 | leak | **0.14** | 2371 | #64892 body (SM90 mHC overlap; part of the stack) |
| C1 | clean | 0.02 | 1948 | CUDA guide, thread block clusters |
| C2 | clean | 0.03 | 3234 | PTX ISA, wgmma |
| C3 | clean | 0.03 | 2661 | #61868 body (GB300 executor, hard negative) |
| C4 | clean | 0.04 | 2233 | base specialized_decode AGENTS.md (hard negative) |
| C5 | clean | 0.09 | 2802 | #62958 DSpark Markov walk on Hopper (hard negative) |

- At threshold **0.30**, recall is 4/5 and false positives 0/5. The miss (L5) is caught by the deterministic layer (PR number
  64892, branch `mgoin/dsv41-sm90-fused-mhc-boundary`, number ≥ 64883).
- The leaks score only 0.55–0.75, so Jev is weakly calibrated here. That is why the blocklist goes first and Jev is the
  second layer.
- **Cost:** 10 paid calls, **$0.000794 total, $0.000079 per call** (mean ~1.9k input tokens). Latency 0.85–1.3 s per call.
- Projection: a heavy agent cycle that fetches 200 pages of ~4 chunks each is 800 calls ≈ **$0.06**. The cache never
  pays twice for the same chunk.

## Not covered
- N=10 is too small to bound the error rates; the ~30-page false-positive test widens it (needs the go below).
- The question wording was not tuned (tuning needs more paid calls).
- Adversarial text in a page could steer Jev; the deterministic layer does not depend on it.
