"""Real searches, the way the agent does them (opencode's websearch tool = Exa MCP `web_search_exa`), with and without the filter.

RAW      = the same request sent from the host through Webshare only (judge side; the agent never sees it).
FILTERED = the same request through the agent's proxy (10.88.0.1:8080), i.e. exactly what opencode receives.
Each result block (Exa returns one text block per result) is scored for leakage with the deterministic rules and the Haiku
judge (the evaluator, not the filter's decision). Output: tests/real_search-<label>.json + a table.
Usage: python3 tests/real_search_test.py <label>"""
import json, re, sys, time
from pathlib import Path
import requests
HERE = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(HERE)); sys.path.insert(0, "/workspace")
from rules import content_hits
from haiku_judge import Judge
from tools.net import proxy_url

QUERIES = [
    ("leak", "DeepSeek V4.1 Hopper specialized decode vLLM"),
    ("leak", "vllm latency_specialized decode backend H200"),
    ("leak", "mgoin Hopper kernels DeepSeek V4.1 decode"),
    ("leak", "SemiAnalysis agent swarm 10,000 lines ultra-fused Hopper kernels"),
    ("leak", "vllm pull request 64893"),
    ("leak", "DeepSeek-V4.1-Flash H200 TP4 decode inter-token latency"),
    ("neutral", "CUTLASS CuTe wgmma tutorial Hopper"),
    ("neutral", "FlashMLA sparse attention decode kernel"),
]
CA = str(HERE / "certs" / "mitmproxy-ca-cert.pem")
import os
_F = os.environ.get("FILTER_PROXY", "http://10.88.0.1:8080")
FILTER = {"http": _F, "https": _F}


def exa(query, proxies, verify):
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "web_search_exa", "arguments": {"query": query, "numResults": 8}}}
    r = requests.post("https://mcp.exa.ai/mcp", json=body, proxies=proxies, verify=verify, timeout=120,
                      headers={"Accept": "application/json, text/event-stream"})
    return r.status_code, r.text


def blocks(text):
    """Split an Exa MCP reply into per-result texts (results are separated by 'Title:' headers in the text payload)."""
    payload = text
    for line in text.splitlines():
        if line.startswith("data:"):
            try:
                j = json.loads(line[5:])
                payload = "\n".join(c.get("text", "") for c in j.get("result", {}).get("content", []))
            except Exception:
                pass
    parts = re.split(r"(?=^Title: )", payload, flags=re.M)
    return [p.strip() for p in parts if p.strip()]


def main():
    label = sys.argv[1] if len(sys.argv) > 1 else "run"
    judge = Judge(str(HERE / "logs" / "haiku_judge_eval.sqlite"), daily_cap_usd=0.30)  # evaluator ledger, separate
    ws = proxy_url(); RAW = {"http": ws, "https": ws}
    rows = []
    for kind, q in QUERIES:
        out = {"kind": kind, "query": q}
        for name, prox, ver in (("raw", RAW, True), ("filtered", FILTER, CA)):
            st, txt = exa(q, prox, ver)
            bl = blocks(txt) if st == 200 else []
            leaky = []
            for b in bl:
                if "removed by the network filter" in b and len(b) < 200:
                    continue
                h = content_hits(b)
                try:
                    jd = judge.judge(b)
                except Exception as e:
                    jd = {"leak": None, "reason": str(e)[:80]}
                if h or jd.get("leak"):
                    leaky.append({"rules": h, "judge": jd.get("leak"), "head": b[:120]})
            out[name] = {"status": st, "results": len(bl), "leaky_results": len(leaky),
                         "redaction_markers": txt.count("removed by the network filter"),
                         "redacted_items": txt.count("redacted_by_network_filter"), "leaky": leaky}
            time.sleep(1)
        rows.append(out)
        r, f = out["raw"], out["filtered"]
        print(f"{kind:7} | raw {r['status']} {r['results']} results, {r['leaky_results']} leaky | filtered {f['status']} "
              f"{f['results']} results, {f['leaky_results']} leaky, markers {f['redaction_markers']} | {q}")
    tot_raw = sum(x["raw"]["leaky_results"] for x in rows); tot_f = sum(x["filtered"]["leaky_results"] for x in rows)
    summary = {"leaky_results_raw": tot_raw, "leaky_results_reaching_agent": tot_f,
               "evaluator_spend_today_usd": round(judge.spent_today(), 4)}
    json.dump({"label": label, "rows": rows, "summary": summary}, open(HERE / "tests" / f"real_search-{label}.json", "w"), indent=1)
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
