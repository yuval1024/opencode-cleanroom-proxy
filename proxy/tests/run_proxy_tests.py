"""End-to-end proxy tests through the live proxy at 10.88.0.1:8080 (run from the host).
Usage: python3 tests/run_proxy_tests.py <label>   -> tests/results-<label>.json
Cases: leak URLs must be 403; leak searches must come back with no leak left in the text; neutral pages must come back
200 with no redaction. "Leak left in the text" = rules.content_hits() on the returned text, or the strings 64893/64892."""
import json, sys, time
from pathlib import Path
import requests
HERE = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(HERE))
from rules import content_hits
P = {"http": "http://10.88.0.1:8080", "https": "http://10.88.0.1:8080"}
CA = str(HERE / "certs" / "mitmproxy-ca-cert.pem")
label = sys.argv[1] if len(sys.argv) > 1 else "run"
UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/141 Safari/537.36"}
LEAK_URLS = [
    "https://github.com/vllm-project/vllm/pull/64893",
    "https://github.com/vllm-project/vllm/pull/64893.diff",
    "https://patch-diff.githubusercontent.com/raw/vllm-project/vllm/pull/64893.diff",
    "https://api.github.com/repos/vllm-project/vllm/pulls/64893",
    "https://api.github.com/repos/vllm-project/vllm/pulls/64893/files",
    "https://github.com/vllm-project/vllm/pull/64892",
    "https://github.com/mgoin/vllm/tree/mgoin/dsv41-hopper-specialized-decode",
    "https://github.com/vllm-project/vllm/compare/main...mgoin:vllm:mgoin/dsv41-hopper-specialized-decode",
    "https://x.com/SemiAnalysis_/status/2116666571728863431",
    "https://github.com/vllm-project/vllm/pull/63921",
]
QUERY = "DeepSeek V4.1 Hopper specialized decode"
SEARCHES = [
    ("ddg-html", "GET", "https://html.duckduckgo.com/html/?q=" + requests.utils.quote(QUERY), None),
    ("ddg-html-2", "GET", "https://html.duckduckgo.com/html/?q=" + requests.utils.quote("vllm H200 latency_specialized decode backend"), None),
    ("github-search-api", "GET", "https://api.github.com/search/issues?q=" + requests.utils.quote("repo:vllm-project/vllm hopper specialized decode"), None),
    ("exa-mcp", "POST", "https://mcp.exa.ai/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "web_search_exa", "arguments": {"query": QUERY, "numResults": 8}}}),
]
out = {"label": label, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "leak_urls": [], "searches": [], "neutral": []}
def leak_left(t):
    """Per item for JSON result lists (what the agent reads item by item), else over the whole text."""
    try:
        from chunking import json_items, item_text
        items, _ = json_items(json.loads(t))
        if items is not None:
            hits = set()
            for x in items:
                s = item_text(x)
                hits.update(content_hits(s) + (["pr-number"] if ("64893" in s or "64892" in s) else []))
            return sorted(hits)
    except Exception:
        pass
    return content_hits(t) + (["pr-number"] if ("64893" in t or "64892" in t) else [])
def get(method, url, body=None, _retry=True):
    h = dict(UA)
    if body is not None:
        h["Accept"] = "application/json, text/event-stream"
    try:
        r = requests.request(method, url, json=body, headers=h, proxies=P, verify=CA, timeout=120)
        if r.status_code == 429 and _retry:
            time.sleep(5); return get(method, url, body, _retry=False)
        return r.status_code, r.text, r.headers.get("content-type", "")
    except Exception as e:
        return -1, f"{type(e).__name__}: {e}", ""
for u in LEAK_URLS:
    st, t, _ = get("GET", u)
    out["leak_urls"].append({"url": u, "status": st, "pass": st == 403}); print("LEAK-URL", st, "PASS" if st == 403 else "FAIL", u)
for name, m, u, b in SEARCHES:
    st, t, ct = get(m, u, b)
    left = leak_left(t)
    ok = st == 403 or (st == 200 and not left)
    out["searches"].append({"name": name, "url": u, "status": st, "ctype": ct, "leak_left": left, "redaction_markers": t.count("removed by the network filter"),
                            "chars": len(t), "pass": ok})
    print("SEARCH", name, st, "markers", t.count("removed by the network filter"), "left", left, "PASS" if ok else "FAIL")
for u in (HERE / "tests" / "neutral_urls.txt").read_text().split():
    st, t, ct = get("GET", u)
    red = t.count("removed by the network filter")
    ok = st == 200 and red == 0
    # a redaction is a TRUE positive when the removed text really references the fix (judged from logs/removed by rule)
    out["neutral"].append({"url": u, "status": st, "redactions": red, "chars": len(t), "pass": ok})
    print("NEUTRAL", st, "red", red, "PASS" if ok else "FAIL", u)
n = out["neutral"]; ok200 = [x for x in n if x["status"] == 200]
out["summary"] = {
    "leak_urls_blocked": f'{sum(x["pass"] for x in out["leak_urls"])}/{len(out["leak_urls"])}',
    "searches_clean": f'{sum(x["pass"] for x in out["searches"])}/{len(out["searches"])}',
    "neutral_fetched_200": f"{len(ok200)}/{len(n)}",
    "neutral_false_positive_pages": sum(1 for x in ok200 if x["redactions"]) + sum(1 for x in n if x["status"] == 403),
    "neutral_fp_rate_over_fetched": (sum(1 for x in ok200 if x["redactions"]) + sum(1 for x in n if x["status"] == 403)) / max(1, len(ok200) + sum(1 for x in n if x["status"] == 403)),
}
json.dump(out, open(HERE / "tests" / f"results-{label}.json", "w"), indent=1)
print(json.dumps(out["summary"]))
