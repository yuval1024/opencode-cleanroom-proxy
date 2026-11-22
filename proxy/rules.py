"""Deterministic layer of the clean-room filter. Pure functions, no I/O except loading rules_data at import.

url_verdict(method, url) -> Verdict(action, rule)
  action: "pass"   – forward, log, never inspect (Anthropic API only)
          "block"  – answer 403 with NEUTRAL_403, never contact upstream
          "binary" – forward unmodified, log as unclassified (git packs of other repos, wheels, tarballs, images)
          "filter" – forward, then classify the response content (content_hits + Jev)
content_hits(text) -> list of rule names that fire on this text chunk (each hit means: redact the chunk)
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, unquote

BASE_SHA = "e5196e2959a42908313510f55fa21f213a48802e"
PR_CUTOFF = 64883                 # first vllm-project/vllm issue/PR number created after the base commit (BASE.md)
FIX_PRS = {64893, 64892, 63921, 64802}  # fix, its SM90 stack piece, post-base latency_specialized extension, humming pin PR page
TWEET_IDS = {"2116666571728863431"}
FIX_SHAS = {"382b4f475f2d8d7ad0adddae0f7a6e4f3313ed80", "e407912bdcaf5f2ed8ed26a2c53f3227bf492957",
            "c58e7f6d05"}
NEUTRAL_403 = ("403 Forbidden\n\nThis resource is not available from this environment's network filter.\n"
               "Use the local vLLM checkout and public documentation instead.\n")
REDACTION = "\n\n[... a section of this page was removed by the network filter ...]\n\n"

_DATA = Path(__file__).with_name("rules_data")
try:
    _ANCESTORS = set(l.strip() for l in (_DATA / "vllm_base_ancestors.txt").read_text().split())
except FileNotFoundError:          # tests can run without it; then no sha is treated as an ancestor
    _ANCESTORS = set()
_ANC_PREFIX = {}                   # 7..12-char prefixes for short-sha URLs
for s in _ANCESTORS:
    for n in (7, 8, 9, 10, 12):
        _ANC_PREFIX.setdefault(s[:n], s)

PASS_HOSTS = {"api.anthropic.com"}
GITHUB_HOSTS = {"github.com", "www.github.com", "api.github.com", "raw.githubusercontent.com", "codeload.github.com",
                "patch-diff.githubusercontent.com", "objects.githubusercontent.com", "gist.github.com",
                "github-production-user-asset-6210df.s3.amazonaws.com"}
X_HOSTS = {"x.com", "twitter.com", "www.x.com", "www.twitter.com", "mobile.twitter.com", "api.x.com", "api.twitter.com",
           "nitter.net", "xcancel.com", "fxtwitter.com", "vxtwitter.com", "fixupx.com", "syndication.twitter.com",
           "cdn.syndication.twimg.com", "publish.twitter.com", "threadreaderapp.com"}
INDEX_HOSTS = {"registry.npmjs.org", "registry.yarnpkg.com", "download.pytorch.org", "download-r2.pytorch.org",
               "pypi.nvidia.com", "files.pythonhosted.org", "astral.sh", "releases.astral.sh"}
BINARY_EXT = re.compile(r"\.(whl|tar\.gz|tgz|zip|tar|gz|bz2|xz|zst|so|bin|pt|safetensors|png|jpe?g|gif|webp|ico|woff2?|ttf|pdf)$", re.I)


@dataclass(frozen=True)
class Verdict:
    action: str
    rule: str


def _is_base_ancestor(ref: str) -> bool:
    ref = ref.lower()
    if re.fullmatch(r"[0-9a-f]{40}", ref):
        return ref in _ANCESTORS
    if re.fullmatch(r"[0-9a-f]{7,12}", ref):
        return ref in _ANC_PREFIX
    return False


def _vllm_github(host: str, parts: list[str]) -> Verdict | None:
    """parts = path segments after owner/repo for vllm-project/vllm (api: after repos/vllm-project/vllm)."""
    if not parts:
        return Verdict("filter", "vllm-repo-home")
    head = parts[0]
    if head in ("pull", "pulls", "issues") and len(parts) > 1 and parts[1].split(".")[0].isdigit():
        n = int(parts[1].split(".")[0])
        if n in FIX_PRS:
            return Verdict("block", f"vllm-fix-pr-{n}")
        if n >= PR_CUTOFF:
            return Verdict("block", f"vllm-pr-after-base>={PR_CUTOFF}")
        if len(parts) > 2 and parts[2] in ("commits", "files", "reviews") or parts[1].endswith((".diff", ".patch")):
            return Verdict("filter", "vllm-old-pr-subpage")
        return Verdict("filter", "vllm-old-pr")
    if head in ("compare",):
        return Verdict("block", "vllm-compare")
    if head in ("info", "git-upload-pack", "git-receive-pack") or head.endswith(".git"):
        return Verdict("block", "vllm-git-protocol (use the local checkout)")
    if head in ("commit", "commits", "tree", "blob", "raw", "blame", "archive", "zipball", "tarball", "git", "contents"):
        rest = parts[1:]
        if head == "git" and rest[:1] in (["commits"], ["trees"], ["blobs"]):
            rest = rest[1:]
        if head == "contents":   # api /contents/path?ref= handled by caller via query; default ref = main (after base)
            return Verdict("block", "vllm-contents-default-ref")
        if not rest:
            return Verdict("block", f"vllm-{head}-listing")
        ref = rest[0]
        for ext in (".diff", ".patch", ".tar.gz", ".zip"):
            if ref.endswith(ext):
                ref = ref[: -len(ext)]
        if ref.lower() in FIX_SHAS or any(ref.lower().startswith(s[:10]) for s in FIX_SHAS):
            return Verdict("block", "vllm-fix-sha")
        if _is_base_ancestor(ref):
            return Verdict("filter", "vllm-ref-at-or-before-base")
        return Verdict("block", "vllm-ref-not-ancestor-of-base")
    if head in ("branches", "tags", "releases", "activity", "network", "graphs", "pulse", "forks", "stargazers"):
        return Verdict("block", f"vllm-{head}")
    if head in ("search",):
        return Verdict("block", "vllm-repo-search")
    return Verdict("filter", f"vllm-{head}")


def url_verdict(method: str, url: str) -> Verdict:
    u = urlsplit(url)
    host = (u.hostname or "").lower()
    path = unquote(u.path or "/")
    full = unquote(url).lower()
    if host in PASS_HOSTS:
        return Verdict("pass", "anthropic-api-passthrough")
    # anywhere: tweet id, fix shas, mgoin fix branches
    for t in TWEET_IDS:
        if t in full:
            return Verdict("block", "semianalysis-tweet-id")
    for s in FIX_SHAS:
        if s[:10] in full:
            return Verdict("block", "fix-sha-in-url")
    if re.search(r"dsv41-(hopper|sm90)", full):
        return Verdict("block", "fix-branch-name-in-url")
    if host in X_HOSTS:
        if re.search(r"semianalysis|mgoin", full):
            return Verdict("block", "x-semianalysis-or-mgoin")
        return Verdict("filter", "x-other")
    if host in GITHUB_HOSTS or host.endswith(".githubusercontent.com"):
        segs = [s for s in path.split("/") if s]
        low = [s.lower() for s in segs]
        if "mgoin" in low or any(s.startswith("mgoin") for s in low):
            return Verdict("block", "github-mgoin")
        if host == "api.github.com":
            if low[:1] == ["search"]:
                return Verdict("filter", "github-api-search")
            if low[:3] == ["repos", "vllm-project", "vllm"]:
                return _vllm_github(host, low[3:])
            if low[:1] == ["users"] and "mgoin" in low:
                return Verdict("block", "github-mgoin")
            return Verdict("filter", "github-api-other")
        if host == "patch-diff.githubusercontent.com" and low[:3] == ["raw", "vllm-project", "vllm"]:
            return _vllm_github(host, low[3:])
        if host == "raw.githubusercontent.com" and low[:2] == ["vllm-project", "vllm"]:
            return _vllm_github(host, ["raw"] + low[2:])
        if host == "codeload.github.com" and low[:2] == ["vllm-project", "vllm"]:
            return _vllm_github(host, ["archive"] + low[3:])
        if low[:2] == ["vllm-project", "vllm"] or low[:2] == ["vllm-project", "vllm.git"]:
            if low[1] == "vllm.git":
                return Verdict("block", "vllm-git-protocol (use the local checkout)")
            return _vllm_github(host, low[2:])
        if len(low) >= 3 and (low[2] in ("info", "git-upload-pack") or low[1].endswith(".git")):
            return Verdict("binary", "git-protocol-other-repo")
        if BINARY_EXT.search(path):
            return Verdict("binary", "github-binary-asset")
        return Verdict("filter", "github-other")
    if host in INDEX_HOSTS or (host == "pypi.org" and (path.startswith("/simple") or path.startswith("/pypi/"))):
        if host in ("files.pythonhosted.org",) and re.search(r"/vllm-\d[^/]*\.(whl|tar\.gz)$", path, re.I):
            return Verdict("block", "pypi-vllm-artifact (use the local checkout)")
        if BINARY_EXT.search(path):
            return Verdict("binary", "package-artifact")
        return Verdict("index", "package-index (rules only)")
    if host in ("files.pythonhosted.org", "pypi.org") and re.search(r"/vllm-\d[^/]*\.(whl|tar\.gz)$", path, re.I):
        return Verdict("block", "pypi-vllm-artifact (use the local checkout)")
    if host.endswith("wheels.vllm.ai") or host == "vllm-wheels.s3.amazonaws.com":
        return Verdict("block", "vllm-nightly-wheels")
    if host in ("files.pythonhosted.org", "registry.npmjs.org", "registry.yarnpkg.com", "download.pytorch.org",
                "pypi.nvidia.com", "developer.download.nvidia.com") and BINARY_EXT.search(path):
        return Verdict("binary", "package-artifact")
    if BINARY_EXT.search(path):
        return Verdict("binary", "binary-extension")
    return Verdict("filter", "default")


# ---- content rules: any hit -> the chunk is redacted -------------------------------------------------------------
_HOPPER = r"(?:sm[_ ]?90a?|hopper|h100|h200|h800|h20\b|gh200)"
_CONTENT_RULES: list[tuple[str, re.Pattern]] = [
    ("fix-pr-number", re.compile(r"(?:#|pull/|pulls/|issues/|\bPR\s?)(?:64893|64892|63921)\b", re.I)),
    ("fix-branch", re.compile(r"dsv41-(?:hopper|sm90)|mgoin/dsv41", re.I)),
    ("fix-sha", re.compile(r"382b4f475f|e407912bdc|c58e7f6d05", re.I)),
    ("tweet-id", re.compile(r"2116666571728863431")),
    ("tweet-claim", re.compile(r"(?:10[,.]?000|10k|ten thousand|一万|1万)\s*(?:LoC|lines|行).{0,160}" + _HOPPER
                               + r"|" + _HOPPER + r".{0,160}(?:10[,.]?000|10k|一万|1万)\s*(?:LoC|lines|行)", re.I | re.S)),
    ("ultra-fused-hopper", re.compile(r"ultra[- ]?fused\s+" + _HOPPER, re.I)),
    ("hopper-decode-38pct", re.compile(_HOPPER + r".{0,200}(?:decode|ITL|token).{0,120}\b38\s?%|\b38\s?%.{0,200}" + _HOPPER, re.I | re.S)),
    ("specialized_decode/hopper-path", re.compile(r"specialized_decode/hopper|test_hopper\.py", re.I)),
]


_HOP = re.compile(_HOPPER, re.I)
_LATSPEC = re.compile(r"latency[_ -]specialized", re.I)
_SPECDEC = re.compile(r"specialized[_ -]decode", re.I)
_DSV41 = re.compile(r"deepseek[- _]?v4\.1|dsv4\.?1|deepseek_v41", re.I)
_MGOIN = re.compile(r"\bmgoin", re.I)
_DEEPSEEK = re.compile(r"deepseek|dsv4", re.I)


def _near(a: re.Pattern, b: re.Pattern, text: str, dist: int) -> bool:
    pa = [m.start() for m in a.finditer(text)]
    if not pa:
        return False
    pb = [m.start() for m in b.finditer(text)]
    return any(abs(x - y) <= dist for x in pa for y in pb)


_SWARM = re.compile(r"agent[- ]?swarm|swarm of agents", re.I)
_SWARM_OBJ = re.compile(r"kernel|\bLoC\b|lines of code|lines|" + _HOPPER, re.I)
_TENK = re.compile(r"10[,.]?000|10k\b|ten thousand", re.I)

# co-occurrence rules (linear time): name -> predicate
_COOC = [
    ("mgoin-near-hopper", lambda t: _near(_MGOIN, _HOP, t, 300)),
    ("agent-swarm+kernels", lambda t: _near(_SWARM, _SWARM_OBJ, t, 200)),
    ("mgoin+10k", lambda t: _near(_MGOIN, _TENK, t, 300)),
    ("latency-specialized+hopper", lambda t: _near(_LATSPEC, _HOP, t, 600)),
    ("specialized-decode+hopper+dsv41", lambda t: _near(_SPECDEC, _HOP, t, 1500) and bool(_DSV41.search(t))),
    ("mgoin+hopper+deepseek+decode", lambda t: bool(_MGOIN.search(t)) and _near(_HOP, _DEEPSEEK, t, 1500)
        and bool(re.search(r"decode|specialized", t, re.I))),
]


_VLLM_AT = re.compile(r"vllm-project/vllm@([0-9a-f]{7,40})\b", re.I)
_VLLM_COMMIT = re.compile(r"github\.com/vllm-project/vllm/commit/([0-9a-f]{7,40})", re.I)
_VLLM_NUM = re.compile(r"github\.com/vllm-project/vllm/(?:pull|issues)/(\d{4,6})", re.I)


def _post_base_refs(text: str) -> bool:
    """Links in the text to vLLM work after the base: a commit that is not an ancestor, or a PR/issue opened after it."""
    if _ANCESTORS:
        for rx in (_VLLM_AT, _VLLM_COMMIT):
            for m in rx.finditer(text):
                if not _is_base_ancestor(m.group(1)):
                    return True
    return any(int(m.group(1)) >= PR_CUTOFF or int(m.group(1)) in FIX_PRS for m in _VLLM_NUM.finditer(text))


def content_hits(text: str) -> list[str]:
    hits = [name for name, rx in _CONTENT_RULES if rx.search(text)]
    if _post_base_refs(text):
        hits.append("links-post-base-vllm-work")
    hits += [name for name, f in _COOC if f(text)]
    return hits
