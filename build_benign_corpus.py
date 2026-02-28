#!/usr/bin/env python3
"""
build_benign_corpus.py — Fetch benign documents from public APIs for corpus expansion.
Sources: arXiv abstracts, Wikipedia summaries, GitHub READMEs (top OSS projects).
All content is public domain or openly licensed. No scraping of live web pages.
"""
import urllib.request, urllib.parse, json, re, time, xml.etree.ElementTree as ET
from pathlib import Path

OUT_DIR = Path(__file__).parent / "tests/benign/corpus"
OUT_DIR.mkdir(parents=True, exist_ok=True)

def fetch(url, delay=0.5):
    req = urllib.request.Request(url, headers={"User-Agent": "prompt-lint-corpus-builder/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            time.sleep(delay)
            return r.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"  fetch error {url}: {e}")
        return None

def clean_text(text):
    """Strip HTML tags and normalize whitespace."""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

# ---------------------------------------------------------------------------
# 1. arXiv abstracts (CS: AI, LG, CL, RO, SE)
# ---------------------------------------------------------------------------
print("=== arXiv abstracts ===")
categories = ["cs.AI", "cs.LG", "cs.CL", "cs.RO", "cs.SE", "cs.AR", "cs.PL"]
arxiv_count = 0
for cat in categories:
    url = (f"http://export.arxiv.org/api/query?"
           f"search_query=cat:{cat}&start=0&max_results=15&sortBy=submittedDate&sortOrder=descending")
    xml_text = fetch(url, delay=1.0)
    if not xml_text:
        continue
    try:
        root = ET.fromstring(xml_text)
        ns = {"atom": "http://www.w3.org/2005/Atom"}
        entries = root.findall("atom:entry", ns)
        for i, entry in enumerate(entries):
            title = entry.findtext("atom:title", namespaces=ns) or ""
            abstract = entry.findtext("atom:summary", namespaces=ns) or ""
            title = re.sub(r"\s+", " ", title).strip()
            abstract = re.sub(r"\s+", " ", abstract).strip()
            if len(abstract) < 100:
                continue
            fname = OUT_DIR / f"arxiv_{cat.replace('.','_')}_{i:02d}.md"
            fname.write_text(f"# {title}\n\n{abstract}\n")
            arxiv_count += 1
        print(f"  {cat}: {len(entries)} entries fetched")
    except Exception as e:
        print(f"  parse error {cat}: {e}")

print(f"  Total arXiv: {arxiv_count} documents")

# ---------------------------------------------------------------------------
# 2. Wikipedia summaries (technology, science topics)
# ---------------------------------------------------------------------------
print("\n=== Wikipedia summaries ===")
topics = [
    "Transformer_(machine_learning_model)", "BERT_(language_model)", "GPT-4",
    "Reinforcement_learning", "Convolutional_neural_network", "Large_language_model",
    "Retrieval-augmented_generation", "Attention_(machine_learning)", "Python_(programming_language)",
    "Rust_(programming_language)", "WebAssembly", "Kubernetes", "Docker_(software)",
    "REST_API", "GraphQL", "TCP/IP", "TLS_(cryptography)", "OAuth",
    "Federated_learning", "Differential_privacy", "Zero-knowledge_proof",
    "Blockchain", "IPFS", "WebRTC", "WebSocket",
    "Space_launch_vehicle", "Ion_thruster", "Solar_panel",
    "CRISPR", "mRNA_vaccine", "Quantum_computing",
]
wiki_count = 0
for topic in topics:
    url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{urllib.parse.quote(topic)}"
    data = fetch(url, delay=0.3)
    if not data:
        continue
    try:
        obj = json.loads(data)
        title = obj.get("title", topic)
        extract = obj.get("extract", "")
        if len(extract) < 100:
            continue
        fname = OUT_DIR / f"wiki_{re.sub(r'[^a-z0-9]', '_', topic.lower())[:50]}.md"
        fname.write_text(f"# {title}\n\n{extract}\n")
        wiki_count += 1
    except Exception as e:
        print(f"  parse error {topic}: {e}")

print(f"  Total Wikipedia: {wiki_count} documents")

# ---------------------------------------------------------------------------
# 3. GitHub READMEs (popular OSS projects)
# ---------------------------------------------------------------------------
print("\n=== GitHub READMEs ===")
repos = [
    "python/cpython", "rust-lang/rust", "golang/go",
    "fastapi/fastapi", "tiangolo/sqlmodel", "pydantic/pydantic",
    "huggingface/transformers", "pytorch/pytorch",
    "langchain-ai/langchain", "openai/openai-python",
    "microsoft/vscode", "neovim/neovim",
    "vitejs/vite", "facebook/react", "vuejs/vue",
    "kubernetes/kubernetes", "docker/compose",
    "anthropics/anthropic-sdk-python", "mistralai/mistral-common",
    "astral-sh/uv", "astral-sh/ruff",
]
import base64
gh_count = 0
for repo in repos:
    url = f"https://api.github.com/repos/{repo}/readme"
    data = fetch(url, delay=0.4)
    if not data:
        continue
    try:
        obj = json.loads(data)
        content_b64 = obj.get("content", "")
        content = base64.b64decode(content_b64).decode("utf-8", errors="replace")
        # Strip badges and excessive markdown, keep first 2000 chars
        content = re.sub(r"!\[.*?\]\(.*?\)", "", content)  # images
        content = re.sub(r"\[!\[.*?\]\(.*?\)\]\(.*?\)", "", content)  # badge links
        content = content[:3000]
        if len(content.strip()) < 200:
            continue
        fname = OUT_DIR / f"github_{repo.replace('/', '_')[:50]}.md"
        fname.write_text(content)
        gh_count += 1
    except Exception as e:
        print(f"  error {repo}: {e}")

print(f"  Total GitHub READMEs: {gh_count} documents")
print(f"\nTotal benign corpus additions: {arxiv_count + wiki_count + gh_count} documents")
print(f"Saved to: {OUT_DIR}")
