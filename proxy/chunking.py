"""Turn a response body into classifiable items and put redacted items back together."""
from __future__ import annotations
import json, re

CHUNK = 4000          # chars per text chunk (~1k tokens); paragraphs are kept whole when possible


def chunk_text(text: str, size: int = CHUNK) -> list[str]:
    paras = re.split(r"(\n\s*\n)", text)
    out, cur = [], ""
    for p in paras:
        if len(cur) + len(p) > size and cur:
            out.append(cur); cur = ""
        while len(p) > size:
            out.append(p[:size]); p = p[size:]
        cur += p
    if cur.strip():
        out.append(cur)
    return out or [""]


def html_to_text(html: str) -> str:
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html, "html.parser")
        for t in soup(["script", "style", "noscript", "svg"]):
            t.decompose()
        txt = soup.get_text("\n")
    except Exception:
        txt = re.sub(r"<script.*?</script>|<style.*?</style>", " ", html, flags=re.S | re.I)
        txt = re.sub(r"<[^>]+>", " ", txt)
    import html as h
    txt = h.unescape(txt)
    txt = re.sub(r"[ \t\r\f\v]+", " ", txt)
    return re.sub(r"\n\s*\n+", "\n\n", txt).strip()


LIST_KEYS = ("items", "results", "data", "organic", "web", "hits", "nodes", "edges", "files", "commits", "comments")


def json_items(obj):
    """Return (list_container, key) of the main result list in a JSON response, or (None, None)."""
    if isinstance(obj, list) and obj and all(isinstance(x, (dict, list, str)) for x in obj):
        return obj, None
    if isinstance(obj, dict):
        for k in LIST_KEYS:
            v = obj.get(k)
            if isinstance(v, list) and v:
                return v, k
            if isinstance(v, dict):
                for k2 in LIST_KEYS:
                    v2 = v.get(k2)
                    if isinstance(v2, list) and v2:
                        return v2, f"{k}.{k2}"
    return None, None


def item_text(x) -> str:
    return x if isinstance(x, str) else json.dumps(x, ensure_ascii=False)
