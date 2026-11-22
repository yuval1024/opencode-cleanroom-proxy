"""mitmproxy addon: the clean-room filter in front of the agent.

Run (see run_proxy.sh): mitmdump --set connection_strategy=lazy -s addon.py --listen-host <bridge-ip> --listen-port 8080

Per flow:
  1. rules.url_verdict -> block (403, never contacts upstream) | pass (Anthropic, logged only) | binary | filter
  2. upstream: api.anthropic.com direct; every other host through a Webshare proxy (server_conn.via)
  3. filter: split the response into items (JSON result items, or ~4k-char text chunks), then for each item
       deterministic content rules  -> redact
       else Jev p_leak >= threshold -> redact
     redact the items; if >= BLOCK_FRACTION of the text is redacted, block the whole response.
  4. one line per flow in decisions.jsonl; the removed text goes to logs/removed/<flow>.json (judge side only).
Env: DECISIONS_LOG, REMOVED_DIR, JEV_MODE=off|treg|direct, JEV_DB, JEV_CAP_USD, JEV_MAX_CALLS, JEV_THRESHOLD,
     JEV_FAIL=block|allow, BLOCK_FRACTION, MAX_CHUNKS, WEBSHARE_LIST, USAGE_LOG
"""
from __future__ import annotations
import asyncio, base64, hashlib, json, os, random, sys, threading, time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from mitmproxy import ctx, http

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import rules  # noqa: E402
from chunking import chunk_text, html_to_text, json_items, item_text  # noqa: E402

LOG = Path(os.environ.get("DECISIONS_LOG", HERE / "decisions.jsonl"))
REMOVED = Path(os.environ.get("REMOVED_DIR", HERE / "logs" / "removed"))
USAGE_LOG = Path(os.environ.get("USAGE_LOG", HERE / "logs" / "anthropic_usage.jsonl"))
JEV_MODE = os.environ.get("JEV_MODE", "off")
JEV_THRESHOLD = float(os.environ.get("JEV_THRESHOLD", "0.20"))
JEV_FAIL = os.environ.get("JEV_FAIL", "block")
BLOCK_FRACTION = float(os.environ.get("BLOCK_FRACTION", "0.5"))
MAX_CHUNKS = int(os.environ.get("MAX_CHUNKS", "60"))
RUN_TAG = os.environ.get("RUN_TAG", "")
_lock = threading.Lock()
_pool = ThreadPoolExecutor(max_workers=int(os.environ.get("JEV_WORKERS", "8")))

_jev = None
if JEV_MODE != "off":
    from jev import Jev
    _jev = Jev(os.environ.get("JEV_DB", str(HERE / "logs" / "jev_cache.sqlite")),
               cap_usd=float(os.environ.get("JEV_CAP_USD", "0")), backend="treg" if JEV_MODE == "treg" else "direct",
               max_calls=int(os.environ["JEV_MAX_CALLS"]) if os.environ.get("JEV_MAX_CALLS") else None)

_judge = None
if os.environ.get("HAIKU_JUDGE", "off") == "on":
    from haiku_judge import Judge, combine
    _judge = Judge(os.environ.get("HAIKU_DB", str(HERE / "logs" / "haiku_judge.sqlite")),
                   daily_cap_usd=float(os.environ.get("HAIKU_JUDGE_CAP_USD", "1.0")))
else:
    from haiku_judge import combine

# ---------------- Webshare upstream ----------------
_WS = []
for line in Path(os.environ.get("WEBSHARE_LIST", "/run/secrets/webshare-proxy-list")).read_text().splitlines():
    if line.count(":") == 3:
        ip, port, user, pw = line.strip().split(":")
        _WS.append(((ip, int(port)), "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode()))
if not _WS:
    raise RuntimeError("no Webshare proxies: refusing to run (no direct scraping from our IP)")
_WS_AUTH = {addr: auth for addr, auth in _WS}
_bad: dict = {}


def _pick_ws():
    now = time.time()
    good = [w for w in _WS if _bad.get(w[0], 0) < now]
    return random.choice(good or _WS)


def _log(rec: dict):
    rec.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    if RUN_TAG:
        rec["run"] = RUN_TAG
    with _lock:
        with open(LOG, "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _neutral_403(flow: http.HTTPFlow):
    flow.response = http.Response.make(403, rules.NEUTRAL_403, {"Content-Type": "text/plain; charset=utf-8"})


class Filter:
    # ---- routing + URL rules (before any upstream connection) ----
    def requestheaders(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        v = rules.url_verdict(flow.request.method, url)
        flow.metadata["verdict"] = v
        if v.action == "block":
            _neutral_403(flow)
            _log({"url": url, "method": flow.request.method, "verdict": "block", "rule": v.rule, "stage": "url"})
            return
        host = flow.request.pretty_host.lower()
        if host in rules.PASS_HOSTS:
            flow.server_conn.via = None
            flow.metadata["upstream"] = "direct"
        else:
            addr, _auth = _pick_ws()
            flow.server_conn.via = ("http", addr)
            flow.metadata["upstream"] = f"webshare:{addr[0]}"

    def http_connect_upstream(self, flow: http.HTTPFlow):
        # here flow.server_conn is the tunnel to the upstream proxy itself
        addr = flow.server_conn.address
        auth = _WS_AUTH.get((addr[0], int(addr[1]))) if addr else None
        if auth:
            flow.request.headers["Proxy-Authorization"] = auth

    def error(self, flow: http.HTTPFlow):
        up = flow.metadata.get("upstream", "")
        msg = str(flow.error) if flow.error else ""
        if "Client disconnected" in msg:
            _log({"url": flow.request.pretty_url, "verdict": "client-disconnect", "rule": "client-went-away", "upstream": up})
            return
        if v := flow.metadata.get("verdict"):
            if v.action == "pass":
                self._anthropic_usage(flow, bytes(flow.metadata.get("tee") or b""))
        if up.startswith("webshare:"):
            for addr, _ in _WS:
                if addr[0] == up.split(":", 1)[1]:
                    _bad[addr] = time.time() + 300
        _log({"url": flow.request.pretty_url, "verdict": "error", "rule": "upstream-error", "upstream": up,
              "error": str(flow.error)[:200] if flow.error else None})

    # ---- Anthropic: stream through, tee usage ----
    def responseheaders(self, flow: http.HTTPFlow):
        v = flow.metadata.get("verdict")
        if v and v.action == "pass":
            buf = bytearray()
            flow.metadata["tee"] = buf
            def tee(data: bytes) -> bytes:
                buf.extend(data)
                return data
            flow.response.stream = tee

    def _anthropic_usage(self, flow, raw: bytes):
        usage = {}; model = None
        try:
            text = raw.decode("utf-8", "ignore")
            if text.lstrip().startswith("{"):
                j = json.loads(text); usage = j.get("usage", {}); model = j.get("model")
            else:
                for line in text.splitlines():
                    if not line.startswith("data:"):
                        continue
                    try:
                        ev = json.loads(line[5:])
                    except Exception:
                        continue
                    if ev.get("type") == "message_start":
                        m = ev.get("message", {}); model = m.get("model"); usage.update(m.get("usage", {}))
                    elif ev.get("type") == "message_delta":
                        usage.update({k: v for k, v in ev.get("usage", {}).items() if v is not None})
        except Exception as e:
            usage = {"parse_error": str(e)[:100]}
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "path": flow.request.path.split("?")[0],
               "status": flow.response.status_code if flow.response else None, "model": model, "usage": usage,
               "run": RUN_TAG}
        with _lock:
            with open(USAGE_LOG, "a") as f:
                f.write(json.dumps(rec) + "\n")
        _log({"url": flow.request.pretty_url, "method": flow.request.method, "verdict": "pass",
              "rule": "anthropic-api-passthrough", "status": rec["status"], "model": model,
              "input_tokens": usage.get("input_tokens"), "output_tokens": usage.get("output_tokens")})

    # ---- content filter ----
    async def response(self, flow: http.HTTPFlow):
        v = flow.metadata.get("verdict")
        if v is not None and v.action == "pass" and flow.response is not None:
            raw = bytes(flow.metadata.get("tee") or b"") or (flow.response.raw_content or b"")
            enc = flow.response.headers.get("content-encoding", "")
            if enc and raw:
                try:
                    from mitmproxy.net import encoding
                    raw = encoding.decode(raw, enc)
                except Exception:
                    pass
            self._anthropic_usage(flow, raw)
            return
        if v is None or v.action == "block" or flow.response is None:
            return
        url = flow.request.pretty_url
        ctype = flow.response.headers.get("content-type", "").lower()
        base = {"url": url, "method": flow.request.method, "status": flow.response.status_code, "ctype": ctype[:60],
                "bytes": len(flow.response.raw_content or b""), "upstream": flow.metadata.get("upstream")}
        textual = any(t in ctype for t in ("text/", "json", "xml", "javascript", "event-stream", "x-diff", "x-patch")) or ctype == ""
        if v.action == "index":
            flow.metadata["rules_only"] = True
        if v.action == "binary" or not textual:
            _log({**base, "verdict": "allow-unclassified", "rule": v.rule if v.action == "binary" else "non-text-content"})
            return
        body = flow.response.get_text(strict=False) or ""
        if not body.strip():
            _log({**base, "verdict": "allow", "rule": "empty"}); return
        try:
            await asyncio.get_running_loop().run_in_executor(None, self._filter_body, flow, body, ctype, base, v)
        except Exception as e:  # fail closed
            _neutral_403(flow)
            _log({**base, "verdict": "block", "rule": f"filter-error:{type(e).__name__}", "error": str(e)[:300]})

    def _classify(self, texts: list[str], jev_limit: int | None = None) -> list[dict]:
        """Deterministic on every text; Jev (parallel) on the first jev_limit texts without a rule hit.
        Returns per-text {hits, p, err}; p stays None for texts beyond jev_limit."""
        out = [{"hits": rules.content_hits(t), "p": None, "err": None} for t in texts]
        todo = [i for i, o in enumerate(out) if not o["hits"] and texts[i].strip()]
        if jev_limit is not None:
            todo = [i for i in todo if i < jev_limit]
        if _jev is not None and todo:
            futs = {i: _pool.submit(_jev.classify, texts[i]) for i in todo}
            hfuts = {i: _pool.submit(_judge.judge, texts[i]) for i in todo} if _judge is not None else {}
            for i, f in futs.items():
                try:
                    r = f.result(timeout=120); out[i]["p"] = r["p_leak"]; out[i]["cached"] = r.get("cached")
                except Exception as e:
                    out[i]["err"] = f"{type(e).__name__}: {str(e)[:120]}"
            for i, f in hfuts.items():
                try:
                    h = f.result(timeout=120); out[i]["haiku"] = {"leak": h["leak"], "conf": h["confidence"], "reason": h["reason"][:160]}
                except Exception as e:
                    out[i]["haiku_err"] = f"{type(e).__name__}: {str(e)[:120]}"
        return out

    def _leaky(self, o: dict) -> tuple[bool, str]:
        if o["hits"]:
            return True, "rule:" + ",".join(o["hits"])
        h = o.get("haiku")
        if o["err"] and h is None:
            return (JEV_FAIL == "block"), "jev-error-" + JEV_FAIL
        hz = {"leak": h["leak"], "confidence": h["conf"]} if h else None
        return combine(o["p"], hz, jev_thr=JEV_THRESHOLD)

    def _save_removed(self, flow, url, removed):
        if not removed:
            return
        REMOVED.mkdir(parents=True, exist_ok=True)
        with open(REMOVED / f"{flow.id}.json", "w") as f:
            json.dump({"url": url, "removed": removed}, f, ensure_ascii=False)

    def _filter_mcp(self, flow, body, ctype, base) -> bool:
        """MCP search replies (JSON-RPC, as SSE `data:` lines or plain JSON): judge each search RESULT, drop leaky ones,
        keep the JSON-RPC envelope valid so the agent's tool can still parse it. Returns True if handled."""
        if '"jsonrpc"' not in body or '"content"' not in body:
            return False
        import re as _re
        url = base["url"]; removed, details, total = [], [], 0

        def fix_payload(j):
            nonlocal total
            res = j.get("result") if isinstance(j, dict) else None
            if not isinstance(res, dict) or not isinstance(res.get("content"), list):
                return j
            for c in res["content"]:
                if not isinstance(c, dict) or not isinstance(c.get("text"), str):
                    continue
                parts = [p for p in _re.split(r"(?=^Title: )", c["text"], flags=_re.M) if p.strip()] or [c["text"]]
                verdicts = self._classify(parts, jev_limit=MAX_CHUNKS)
                keep, dropped = [], 0
                for i, (p, o) in enumerate(zip(parts, verdicts)):
                    bad, why = self._leaky(o)
                    details.append({"i": total + i, "n": len(p), "hits": o["hits"], "p": o["p"], "haiku": o.get("haiku"),
                                    "redact": bad, "why": why})
                    if bad:
                        dropped += 1; removed.append({"i": total + i, "why": why, "text": p})
                    else:
                        keep.append(p)
                total += len(parts)
                if dropped:
                    keep.append(f"\n[{dropped} search result(s) removed by the network filter]\n")
                c["text"] = "".join(keep)
            return j

        if "event-stream" in ctype:
            out_lines, changed = [], False
            for line in body.split("\n"):
                if line.startswith("data:"):
                    try:
                        j = json.loads(line[5:])
                    except Exception:
                        out_lines.append(line); continue
                    out_lines.append("data: " + json.dumps(fix_payload(j), ensure_ascii=False)); changed = True
                else:
                    out_lines.append(line)
            if not changed:
                return False
            new = "\n".join(out_lines)
        else:
            try:
                new = json.dumps(fix_payload(json.loads(body)), ensure_ascii=False)
            except Exception:
                return False
        if removed:
            flow.response.set_text(new)
        self._save_removed(flow, url, removed)
        _log({**base, "verdict": "redact" if removed else "allow", "rule": "mcp-search-results", "unit": "search-result",
              "n_items": total, "n_redacted": len(removed), "items": details})
        return True

    def _filter_body(self, flow, body, ctype, base, v):
        url = base["url"]
        if ("event-stream" in ctype or "json" in ctype) and self._filter_mcp(flow, body, ctype, base):
            return
        # JSON with a result list: classify item by item
        if "json" in ctype:
            try:
                obj = json.loads(body)
            except Exception:
                obj = None
            if obj is not None:
                items, key = json_items(obj)
                if items is not None:
                    texts = [item_text(x) for x in items]
                    res = self._classify(texts, jev_limit=0 if flow.metadata.get("rules_only") else MAX_CHUNKS * 2)
                    removed, details = [], []
                    for i, o in enumerate(res):
                        bad, why = self._leaky(o)
                        details.append({"i": i, "n": len(texts[i]), "hits": o["hits"], "p": o["p"], "err": o["err"], "haiku": o.get("haiku"), "redact": bad, "why": why})
                        if bad:
                            removed.append({"i": i, "why": why, "text": texts[i][:20000]})
                            items[i] = {"redacted_by_network_filter": True}
                    over = 0
                    self._save_removed(flow, url, removed)
                    if removed and len(removed) >= BLOCK_FRACTION * len(texts) and len(texts) <= 2:
                        _neutral_403(flow)
                        _log({**base, "verdict": "block", "rule": "json-items-leaky", "unit": "json-item", "items": details}); return
                    if removed or over > 0:
                        flow.response.set_text(json.dumps(obj, ensure_ascii=False))
                    if flow.metadata.get("rules_only"):   # package indexes: keep the log small, details only for hits
                        details = [d for d in details if d["hits"]]
                    _log({**base, "verdict": "redact" if removed else "allow", "rule": f"json-items:{key}", "unit": "json-item",
                          "n_items": len(texts), "n_redacted": len(removed), "jev_unscored": max(0, len(texts) - MAX_CHUNKS * 2), "items": details}); return
        # text / html / other json: chunks
        is_html = "html" in ctype
        text = html_to_text(body) if is_html else body
        chunks = chunk_text(text)
        structured = not is_html and not ctype.startswith("text/")   # json, js, xml: never cut, rules on all, Jev on first MAX
        truncated = (not structured) and len(chunks) > MAX_CHUNKS
        if truncated:
            chunks = chunks[:MAX_CHUNKS]
        res = self._classify(chunks, jev_limit=0 if flow.metadata.get("rules_only") else MAX_CHUNKS)
        out, removed, details, red_chars = [], [], [], 0
        for i, (c, o) in enumerate(zip(chunks, res)):
            bad, why = self._leaky(o)
            details.append({"i": i, "n": len(c), "hits": o["hits"], "p": o["p"], "err": o["err"], "haiku": o.get("haiku"), "redact": bad, "why": why})
            if bad:
                removed.append({"i": i, "why": why, "text": c}); red_chars += len(c); out.append(rules.REDACTION)
            else:
                out.append(c)
        total = sum(len(c) for c in chunks) or 1
        self._save_removed(flow, url, removed)
        if removed and red_chars / total >= BLOCK_FRACTION:
            _neutral_403(flow)
            _log({**base, "verdict": "block", "rule": "mostly-leaky", "unit": "chunk", "n_chunks": len(chunks),
                  "n_redacted": len(removed), "chunks": details}); return
        if structured and removed:
            _neutral_403(flow)   # cannot redact inside structured content safely
            _log({**base, "verdict": "block", "rule": "structured-leaky", "unit": "chunk", "chunks": details}); return
        if removed or truncated:
            new = "".join(out) + ("\n\n[... the rest of this page was truncated by the network filter ...]\n" if truncated else "")
            flow.response.set_text(new)
            if is_html:
                flow.response.headers["content-type"] = "text/markdown; charset=utf-8"
        if flow.metadata.get("rules_only"):
            details = [d for d in details if d["hits"]]
        _log({**base, "verdict": "redact" if removed else ("truncate" if truncated else "allow"),
              "rule": "chunks", "unit": "chunk", "n_chunks": len(chunks), "n_redacted": len(removed),
              "truncated": truncated, "jev_unscored": max(0, len(chunks) - MAX_CHUNKS), "html_converted": bool(is_html and (removed or truncated)), "chunks": details})


addons = [Filter()]
