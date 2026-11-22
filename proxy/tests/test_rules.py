import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pytest
from rules import url_verdict, content_hits, BASE_SHA

BLOCK = [
    "https://github.com/vllm-project/vllm/pull/64893",
    "https://github.com/vllm-project/vllm/pull/64893.diff",
    "https://github.com/vllm-project/vllm/pull/64893.patch",
    "https://github.com/vllm-project/vllm/pull/64893/files",
    "https://github.com/vllm-project/vllm/pull/64892",
    "https://patch-diff.githubusercontent.com/raw/vllm-project/vllm/pull/64893.diff",
    "https://api.github.com/repos/vllm-project/vllm/pulls/64893",
    "https://api.github.com/repos/vllm-project/vllm/pulls/64893/files",
    "https://api.github.com/repos/vllm-project/vllm/issues/64893/comments",
    "https://github.com/vllm-project/vllm/pull/63921",
    "https://github.com/vllm-project/vllm/pull/64990",        # any PR opened after the base
    "https://github.com/vllm-project/vllm/compare/main...mgoin:vllm:mgoin/dsv41-hopper-specialized-decode",
    "https://github.com/vllm-project/vllm/compare/e5196e2959a4...382b4f475f2d",
    "https://github.com/mgoin/vllm/tree/mgoin/dsv41-hopper-specialized-decode",
    "https://github.com/mgoin",
    "https://api.github.com/users/mgoin/events",
    "https://github.com/vllm-project/vllm/commit/382b4f475f2d8d7ad0adddae0f7a6e4f3313ed80",
    "https://github.com/vllm-project/vllm/commit/c58e7f6d05",
    "https://github.com/vllm-project/vllm/blob/main/vllm/models/deepseek_v41/nvidia/specialized_decode/__init__.py",
    "https://raw.githubusercontent.com/vllm-project/vllm/main/README.md",
    "https://github.com/vllm-project/vllm/commits/main",
    "https://github.com/vllm-project/vllm/tree/main",
    "https://github.com/vllm-project/vllm.git/info/refs?service=git-upload-pack",
    "https://github.com/vllm-project/vllm/info/refs?service=git-upload-pack",
    "https://codeload.github.com/vllm-project/vllm/tar.gz/refs/heads/main",
    "https://x.com/SemiAnalysis_/status/2116666571728863431",
    "https://twitter.com/i/web/status/2116666571728863431",
    "https://nitter.net/SemiAnalysis_/status/2116666571728863431",
    "https://x.com/mgoin_",
    "https://files.pythonhosted.org/packages/ab/cd/vllm-0.20.1-cp38-abi3-manylinux1_x86_64.whl",
    "https://wheels.vllm.ai/nightly/vllm-1.0.0.dev-cp38-abi3-manylinux1_x86_64.whl",
    "https://github.com/vllm-project/vllm/branches",
]
FILTER = [
    f"https://github.com/vllm-project/vllm/blob/{BASE_SHA}/vllm/models/deepseek_v41/nvidia/specialized_decode/AGENTS.md",
    f"https://raw.githubusercontent.com/vllm-project/vllm/{BASE_SHA}/README.md",
    "https://github.com/vllm-project/vllm/commit/d0787e48394b214f78694fce3520a8c11eca045c",
    "https://github.com/vllm-project/vllm/commit/d0787e4839",
    "https://github.com/vllm-project/vllm/pull/61868",
    "https://github.com/vllm-project/vllm/pull/57770",
    "https://api.github.com/repos/vllm-project/vllm/pulls/61868",
    "https://docs.nvidia.com/cuda/parallel-thread-execution/index.html",
    "https://docs.vllm.ai/en/latest/",
    "https://github.com/NVIDIA/cutlass/blob/main/media/docs/cpp/cute/0x_gemm_tutorial.md",
    "https://pypi.org/project/humming-kernels/",
    "https://html.duckduckgo.com/html/?q=hopper+wgmma",
    "https://api.github.com/search/issues?q=hopper+specialized+decode",
]
PASS = ["https://api.anthropic.com/v1/messages"]
BINARY = ["https://files.pythonhosted.org/packages/xx/humming_kernels-0.1.19-py3-none-any.whl",
          "https://github.com/NVIDIA/cutlass.git/info/refs?service=git-upload-pack"]

@pytest.mark.parametrize("url", BLOCK)
def test_block(url):
    assert url_verdict("GET", url).action == "block", url_verdict("GET", url)

@pytest.mark.parametrize("url", FILTER)
def test_filter(url):
    assert url_verdict("GET", url).action == "filter", url_verdict("GET", url)

@pytest.mark.parametrize("url", PASS)
def test_pass(url):
    assert url_verdict("POST", url).action == "pass"

@pytest.mark.parametrize("url", BINARY)
def test_binary(url):
    assert url_verdict("GET", url).action == "binary", url_verdict("GET", url)

LEAK_TEXT = [
    "See vllm-project/vllm#64893 for the Hopper backend.",
    "[Perf][DSv4.1] DeepSeek-V4.1-Flash specialized decode on Hopper (H200 TP4)",
    "Add a Hopper (SM90) backend to DeepSeek-V4.1's specialized decode executor",
    "--additional-config '{\"decode_backend\":\"latency_specialized\"}' now works on H200 too",
    "@mgoin_ got his agent swarm to write 10,000 LoC of ultra-fused Hopper kernels that improve decode speeds by up to 38%",
    "mgoin wrote fused SM90 kernels for DeepSeek V4 decode",
    "branch mgoin/dsv41-hopper-specialized-decode",
    "vllm/models/deepseek_v41/nvidia/specialized_decode/hopper/moe_cute.py",
    "Hopper 上一万行融合内核, decode 提速 38%",
    "Title: [Perf] something · vllm-project/vllm@c58e7f6d05ab",
    "see https://github.com/vllm-project/vllm/pull/64990 for details",
]
CLEAN_TEXT = [
    "wgmma.mma_async.sync.aligned.m64n128k16.f32.bf16.bf16 performs warpgroup-level MMA on Hopper (sm_90a).",
    "The latency_specialized decode backend requires GB300 (SM103), TP=4 and DSpark.",
    "DeepSeek-V4.1-Flash is a MoE model with 43 layers; FP8 KV cache is supported on H100 and H200.",
    "Thread block clusters are a feature of compute capability 9.0 (Hopper).",
    "PR #61868 adds the specialized decode on GB300.",
    "Title: GB300 decode · vllm-project/vllm@d0787e4839",
    "https://github.com/vllm-project/vllm/pull/61868 and https://github.com/vllm-project/vllm/blob/main/README.md",
]

@pytest.mark.parametrize("t", LEAK_TEXT)
def test_content_leak(t):
    assert content_hits(t), t

@pytest.mark.parametrize("t", CLEAN_TEXT)
def test_content_clean(t):
    assert not content_hits(t), (t, content_hits(t))
