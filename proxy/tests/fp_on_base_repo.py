"""Deterministic content rules over the base checkout's own text (neutral by definition: it predates the fix)."""
import sys, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from rules import content_hits
from chunking import chunk_text
W = Path("/workspace/vllm")
import subprocess
agent_touched = set(subprocess.run(["git", "-C", str(W), "diff", "--name-only", "12acac46bdd0a28a7cb7048a5f8ea95b493b2be1"], capture_output=True, text=True).stdout.split())
agent_touched |= set(subprocess.run(["git", "-C", str(W), "ls-files", "--others", "--exclude-standard"], capture_output=True, text=True).stdout.split())
files = [p for p in W.rglob("*") if str(p.relative_to(W)) not in agent_touched]
files = [p for p in files if p.is_file() and ".git" not in p.parts and p.suffix in (".md", ".py", ".rst", ".txt", ".yaml", ".cu", ".cuh", ".h")]
n = 0; hits = []
for p in files:
    try: t = p.read_text(errors="ignore")
    except Exception: continue
    for i, c in enumerate(chunk_text(t)):
        n += 1; h = content_hits(c)
        if h: hits.append({"file": str(p.relative_to(W)), "chunk": i, "rules": h})
print(json.dumps({"files": len(files), "chunks": n, "chunks_hit": len(hits), "fp_rate": len(hits) / max(n, 1)}))
for h in hits[:40]: print(h)
