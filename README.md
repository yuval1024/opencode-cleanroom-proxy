# opencode clean-room proxy

A filtering egress proxy that lets an AI coding agent reach the web with **one subject removed**
from everything it fetches — a clean room for testing whether a model can solve a problem without
looking up the answer.

- `proxy/` — the mitmproxy add-on (`addon.py`) and its filter layers: deterministic rules
  (`rules.py`), an LLM classifier (`jev.py`), and a Haiku judge (`haiku_judge.py`), plus tests.
- `opencode/` — the container harness whose only network exit is the proxy, with a no-bypass
  guarantee (`NO-BYPASS.md`, `nobypass_test.sh`).

Keys are read from a file at runtime and are not in this repo.
