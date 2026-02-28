#!/usr/bin/env python3
"""
corpus_analysis.py — N-gram statistical analysis of prompt injection patterns.

Builds first and second order Markov (bigram/trigram) frequency models from
labeled malicious and benign corpora, computes log-likelihood ratios to
identify discriminating n-grams, and saves a compact JSON model for use
by the statistical scorer in prompt_lint.py.

Usage:
  python3 corpus_analysis.py                         # train + report
  python3 corpus_analysis.py --output model.json     # save model
  python3 corpus_analysis.py --top 30                # show top N discriminating grams
"""

import re, json, math, argparse
from pathlib import Path
from collections import Counter

# ---------------------------------------------------------------------------
# Tokenization
# ---------------------------------------------------------------------------

def tokenize(text: str) -> list[str]:
    """Normalize and tokenize text for n-gram analysis.
    Strips markdown formatting, lowercases, splits on whitespace/punctuation.
    Keeps contractions and hyphenated words intact.
    """
    # Strip markdown code blocks (don't want code syntax to dominate)
    text = re.sub(r"```.*?```", " CODE_BLOCK ", text, flags=re.DOTALL)
    text = re.sub(r"`[^`]+`", " INLINE_CODE ", text)
    # Strip URLs
    text = re.sub(r"https?://\S+", " URL ", text)
    # Strip markdown headers/emphasis but keep the words
    text = re.sub(r"[#*_~>|]", " ", text)
    # Strip test case headers [TEST CASE...]
    text = re.sub(r"\[TEST CASE.*?\]", "", text)
    text = re.sub(r"\[EXPECTED:.*?\]", "", text)
    text = re.sub(r"\[Source:.*?\]", "", text)
    # Lowercase, split
    tokens = re.findall(r"[a-z][a-z'\-]*[a-z]|[a-z]", text.lower())
    return tokens

def ngrams(tokens: list[str], n: int) -> list[tuple]:
    return [tuple(tokens[i:i+n]) for i in range(len(tokens) - n + 1)]

# ---------------------------------------------------------------------------
# Corpus loader
# ---------------------------------------------------------------------------

def load_corpus(directory: Path, skip_prefix: str = "[TEST") -> list[str]:
    """Load all .md files from a directory as a list of document strings."""
    docs = []
    for f in sorted(directory.glob("*.md")):
        text = f.read_text(errors="replace")
        docs.append(text)
    return docs

# ---------------------------------------------------------------------------
# Model builder
# ---------------------------------------------------------------------------

def build_model(docs: list[str], ns: list[int] = [1, 2, 3]) -> dict[int, Counter]:
    """Build n-gram frequency counts for each n in ns."""
    models = {n: Counter() for n in ns}
    for doc in docs:
        tokens = tokenize(doc)
        for n in ns:
            models[n].update(ngrams(tokens, n))
    return models

def log_likelihood_ratios(
    mal_model: dict, ben_model: dict,
    n: int, alpha: float = 0.5
) -> list[tuple[float, tuple]]:
    """
    Compute log P(gram | malicious) / P(gram | benign) for each gram.
    Uses Laplace (add-alpha) smoothing to handle zero counts.
    Returns sorted list of (llr, gram) tuples, highest first.
    """
    mal_counts = mal_model[n]
    ben_counts = ben_model[n]

    mal_total = sum(mal_counts.values()) + alpha * len(mal_counts)
    ben_total = sum(ben_counts.values()) + alpha * len(ben_counts)

    all_grams = set(mal_counts) | set(ben_counts)
    ratios = []
    for gram in all_grams:
        p_mal = (mal_counts[gram] + alpha) / mal_total
        p_ben = (ben_counts[gram] + alpha) / ben_total
        llr = math.log2(p_mal / p_ben)
        ratios.append((llr, gram))

    return sorted(ratios, key=lambda x: -x[0])

# ---------------------------------------------------------------------------
# Document scorer
# ---------------------------------------------------------------------------

def score_document(text: str, llr_tables: dict[int, list], top_k: int = 200) -> float:
    """
    Score a document against the LLR tables.
    Positive score = more malicious-like. Negative = more benign-like.
    Uses only the top_k most discriminating grams per order to reduce noise.
    """
    total = 0.0
    tokens = tokenize(text)
    for n, llr_list in llr_tables.items():
        # Build fast lookup dict from top_k most discriminating grams
        lookup = {gram: llr for llr, gram in llr_list[:top_k]}
        doc_grams = ngrams(tokens, n)
        for gram in doc_grams:
            if gram in lookup:
                total += lookup[gram]
    return total

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def print_report(llr_tables: dict, top: int = 20, ns: list[int] = [1, 2, 3]):
    ORDER_NAMES = {1: "Unigrams", 2: "Bigrams (1st-order Markov)", 3: "Trigrams (2nd-order Markov)"}
    for n in ns:
        if n not in llr_tables:
            continue
        ranked = llr_tables[n]
        print(f"\n{'='*60}")
        print(f"  {ORDER_NAMES.get(n, f'{n}-grams')} — top {top} discriminating")
        print(f"{'='*60}")
        print(f"  {'→ MALICIOUS':40s}  {'→ BENIGN':40s}")
        print(f"  {'-'*40}  {'-'*40}")
        mal_top = [(llr, g) for llr, g in ranked if llr > 0][:top]
        ben_top = [(llr, g) for llr, g in reversed(ranked) if llr < 0][:top]
        for i in range(max(len(mal_top), len(ben_top))):
            ml = f"{' '.join(mal_top[i][1]):32s} {mal_top[i][0]:+.2f}" if i < len(mal_top) else ""
            bl = f"{' '.join(ben_top[i][1]):32s} {ben_top[i][0]:+.2f}" if i < len(ben_top) else ""
            print(f"  {ml:44s}  {bl}")

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="N-gram corpus analysis for prompt-lint")
    parser.add_argument("--malicious", default="tests/malicious", help="Malicious corpus directory")
    parser.add_argument("--benign", default="tests/benign", help="Benign corpus directory")
    parser.add_argument("--output", default=None, help="Save model to JSON file")
    parser.add_argument("--top", type=int, default=20, help="Top N n-grams to display")
    parser.add_argument("--test", default=None, help="Score a test file against the model")
    args = parser.parse_args()

    base = Path(__file__).parent
    mal_docs = load_corpus(base / args.malicious)
    ben_docs = load_corpus(base / args.benign)

    print(f"Corpus: {len(mal_docs)} malicious, {len(ben_docs)} benign documents")
    print(f"Malicious tokens: {sum(len(tokenize(d)) for d in mal_docs)}")
    print(f"Benign tokens:    {sum(len(tokenize(d)) for d in ben_docs)}")

    ns = [1, 2, 3]
    mal_model = build_model(mal_docs, ns)
    ben_model = build_model(ben_docs, ns)

    llr_tables = {n: log_likelihood_ratios(mal_model, ben_model, n) for n in ns}

    print_report(llr_tables, top=args.top, ns=ns)

    if args.test:
        text = Path(args.test).read_text(errors="replace")
        score = score_document(text, llr_tables)
        tokens = tokenize(text)
        print(f"\n{'='*60}")
        print(f"  Statistical score for: {args.test}")
        print(f"  Score: {score:+.2f}  ({'malicious-leaning' if score > 0 else 'benign-leaning'})")
        print(f"  Token count: {len(tokens)}")
        print(f"  Normalized: {score/max(len(tokens),1):+.4f} per token")

    if args.output:
        # Serialize — store top 500 grams per order as compact lookup
        model_data = {
            "version": "1.0",
            "corpus_stats": {
                "malicious_docs": len(mal_docs),
                "benign_docs": len(ben_docs),
            },
            "llr_tables": {
                str(n): [[llr, list(gram)] for llr, gram in llr_tables[n][:500]]
                for n in ns
            }
        }
        Path(args.output).write_text(json.dumps(model_data, indent=2))
        print(f"\nModel saved to: {args.output}")

if __name__ == "__main__":
    main()
