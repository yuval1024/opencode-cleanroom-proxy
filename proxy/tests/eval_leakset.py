"""Score the filter on the labelled sets, at item level and chunk level.
Usage: python3 tests/eval_leakset.py deterministic | jev   (jev mode spends: one Jev call per uncached item/chunk)
Sets: tests/leakset.judge.json (leaks: SemiAnalysis thread, PR bodies, synthetic code-only), tests/mixed_page.judge.json
(neutral page + 1 leaking paragraph), neutral pages = chunks logged by the neutral run (fetched fresh here via the proxy)."""
import json, sys
from pathlib import Path
HERE = Path(__file__).resolve().parents[1]; sys.path.insert(0, str(HERE))
from rules import content_hits
from chunking import chunk_text
mode = sys.argv[1] if len(sys.argv) > 1 else "deterministic"
THR = 0.20
jev = None
if mode == "jev":
    from jev import Jev
    jev = Jev(str(HERE / "logs" / "jev_cache.sqlite"), cap_usd=float(sys.argv[2]) if len(sys.argv) > 2 else 0.10, backend="treg")
judge = None
if mode == "full":
    from jev import Jev
    from haiku_judge import Judge
    jev = Jev(str(HERE / "logs" / "jev_cache.sqlite"), cap_usd=0.50, backend="treg")
    judge = Judge(str(HERE / "logs" / "haiku_judge.sqlite"), daily_cap_usd=1.0)
from haiku_judge import combine
def verdict(text):
    h = content_hits(text)
    if h: return True, "rule:" + ",".join(h), None
    if jev is None: return False, "", None
    p = jev.classify(text)["p_leak"]
    if judge is None:
        return p >= THR, f"jev:{p:.2f}", p
    hz = judge.judge(text)
    bad, why = combine(p, hz, jev_thr=THR)
    return bad, why or f"clean(jev:{p:.2f},haiku:{hz['leak']})", p
res = {"mode": mode, "items": [], "mixed": None}
for it in json.load(open(HERE / "tests" / "leakset.judge.json")):
    bad, why, p = verdict(it["text"])
    res["items"].append({"id": it["id"], "kind": it["kind"], "label": it["label"], "caught": bad, "why": why, "p": p, "chars": len(it["text"])})
m = json.load(open(HERE / "tests" / "mixed_page.judge.json"))
chunks = chunk_text(m["text"])
cres = []
for i, c in enumerate(chunks):
    bad, why, p = verdict(c)
    cres.append({"i": i, "has_leak": m["leak_para"][:200] in c or m["leak_para"][-200:] in c, "redacted": bad, "why": why, "p": p})
res["mixed"] = cres
by = {}
for r in res["items"]:
    k = by.setdefault(r["kind"], [0, 0]); k[0] += r["caught"]; k[1] += 1
leak_ch = [c for c in cres if c["has_leak"]]; clean_ch = [c for c in cres if not c["has_leak"]]
res["summary"] = {
    "item_recall_by_kind": {k: f"{a}/{b}" for k, (a, b) in by.items()},
    "item_recall_all": f'{sum(r["caught"] for r in res["items"])}/{len(res["items"])}',
    "mixed_page_chunks": len(cres),
    "mixed_leak_chunks_redacted": f'{sum(c["redacted"] for c in leak_ch)}/{len(leak_ch)}',
    "mixed_clean_chunks_redacted(FP)": f'{sum(c["redacted"] for c in clean_ch)}/{len(clean_ch)}',
}
if jev: res["summary"]["jev_spent_usd_total_ledger"] = round(jev.spent()[0], 6)
if judge: res["summary"]["haiku_judge_spent_today_usd"] = round(judge.spent_today(), 5)
json.dump(res, open(HERE / "tests" / f"eval-leakset-{mode}.json", "w"), indent=1)
print(json.dumps(res["summary"], indent=1))
for r in res["items"]:
    if not r["caught"]: print("MISS", r["id"], r["kind"], r["chars"], "chars")
named = {r["id"]: (r["caught"], r["why"]) for r in res["items"]}
for k in ("X2116666571728863431", "X2116679257145414070", "X2116667541720543554"): print(k, named.get(k))
