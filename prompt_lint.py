#!/usr/bin/env python3
"""
prompt_lint.py — Prompt injection detector for agent research pipelines.
Scans text/markdown files and flags patterns that suggest prompt injection attempts.

Usage:
  python3 prompt_lint.py <file>
  cat file.md | python3 prompt_lint.py -
  python3 prompt_lint.py <file> --format json
  python3 prompt_lint.py <file> --threshold medium
"""

import re, sys, json, argparse
from dataclasses import dataclass, field, asdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Statistical scorer (n-gram Markov model, optional)
# ---------------------------------------------------------------------------

def _load_stat_model(model_path: Path | None = None) -> dict | None:
    """Load the n-gram LLR model if available. Returns None if not found."""
    if model_path is None:
        model_path = Path(__file__).parent / "model.json"
    if not model_path.exists():
        return None
    try:
        return json.load(model_path.open())
    except Exception:
        return None

def _stat_score(text: str, model: dict, top_k: int = 200) -> tuple[float, int]:
    """Score text against the LLR model. Returns (raw_score, token_count)."""
    import re as _re
    # Minimal tokenizer (must match corpus_analysis.py)
    text = _re.sub(r"```.*?```", " ", text, flags=_re.DOTALL)
    text = _re.sub(r"`[^`]+`", " ", text)
    text = _re.sub(r"https?://\S+", " ", text)
    text = _re.sub(r"[#*_~>|]", " ", text)
    text = _re.sub(r"\[.*?\]", "", text)
    tokens = _re.findall(r"[a-z][a-z'\-]*[a-z]|[a-z]", text.lower())
    if len(tokens) < 5:
        return 0.0, 0
    total = 0.0
    for n_str, llr_list in model.get("llr_tables", {}).items():
        n = int(n_str)
        lookup = {tuple(gram): llr for llr, gram in llr_list[:top_k]}
        for i in range(len(tokens) - n + 1):
            gram = tuple(tokens[i:i+n])
            if gram in lookup:
                total += lookup[gram]
    return total, len(tokens)

# ---------------------------------------------------------------------------
# Pattern library
# ---------------------------------------------------------------------------

@dataclass
class Pattern:
    category: str
    severity: str  # low | medium | high | critical
    description: str
    regex: str
    note: str = ""

PATTERNS = [
    # --- Direct instruction override ---
    Pattern("INSTRUCTION_OVERRIDE", "critical",
        "Explicit override of prior instructions",
        r"(?i)(ignore|disregard|forget|override|supersede|bypass|cancel)\s+(?:\w+\s+){0,3}(instructions?|directives?|rules?|constraints?|prompts?|guidelines?)",
        "Classic prompt injection opener"),

    Pattern("INSTRUCTION_OVERRIDE", "critical",
        "System prompt replacement attempt",
        r"(?i)(new|updated?|real|actual|true|revised)\s+(instructions?|system\s+prompt|directives?|rules?|guidelines?)\s*(:|are|follow|below)",
        "Attempts to replace system prompt inline"),

    Pattern("INSTRUCTION_OVERRIDE", "high",
        "Instruction injection via formatting",
        r"(?i)(\[INST\]|\[SYSTEM\]|\[ASSISTANT\]|<\|system\|>|<\|user\|>|<\|im_start\|>|\{\{system\}\})",
        "Attempts to inject role tokens used by LLM chat templates"),

    # --- Role / persona hijacking ---
    Pattern("ROLE_HIJACK", "critical",
        "Identity replacement attempt",
        r"(?i)(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|your\s+new\s+(role|persona|name|identity)\s+is|from\s+now\s+on\s+you\s+(are|will))",
        "Attempts to redefine agent identity"),

    Pattern("ROLE_HIJACK", "high",
        "DAN / jailbreak persona",
        r"(?i)(do\s+anything\s+now|jailbreak(ed)?|unrestricted\s+(AI|mode|version)|without\s+(restrictions?|limits?|filters?|safety)|DAN[\s\-]mode|DAN[\s\-]persona)",
        "Known jailbreak persona patterns"),

    Pattern("ROLE_HIJACK", "medium",
        "Fictional framing for constraint bypass",
        r"(?i)(hypothetically|in\s+a\s+fictional\s+(world|scenario)|for\s+(a\s+story|fiction|a\s+novel))[^\n]{0,80}(how\s+to|instructions?\s+for|steps?\s+to)",
        "Fictional framing used to extract restricted content"),

    # --- Permission escalation ---
    Pattern("PERMISSION_ESCALATION", "critical",
        "Claimed permission grant",
        r"(?i)(you\s+(have\s+been|are)\s+(granted|given|authorized|permitted|allowed)|the\s+(user|admin|owner|developer)\s+has\s+(authorized|granted|approved))",
        "Content claiming to grant elevated permissions"),

    Pattern("PERMISSION_ESCALATION", "high",
        "Developer/admin mode claim",
        r"(?i)(developer\s+mode|admin\s+mode|god\s+mode|maintenance\s+mode|debug\s+mode|override\s+mode)\s*(:|enabled|activated|is\s+on)",
        "Claims of special operational modes"),

    Pattern("PERMISSION_ESCALATION", "medium",
        "Safety disable claim",
        r"(?i)(safety\s+(is\s+)?(disabled?|off|bypassed?|removed?)|content\s+filter(s)?\s+(disabled?|off)|restrictions?\s+(have\s+been\s+)?(lifted|removed|disabled?))",
        "Claims that safety measures are inactive"),

    # --- Exfiltration ---
    Pattern("EXFILTRATION", "critical",
        "System prompt extraction request",
        r"(?i)(print|output|display|reveal|show|repeat|write out|tell me)\s+(?:\w+\s+){0,5}(system\s+prompt|initial\s+instructions?|full\s+prompt|original\s+prompt|all\s+instructions?)",
        "Attempts to extract system prompt"),

    Pattern("EXFILTRATION", "high",
        "File/credential exfiltration",
        r"(?i)(read|output|send|exfiltrate|leak|print)\s+.{0,40}(\.env|secrets?|credentials?|api[_\s]?keys?|password|token|\.ssh|id_rsa)",
        "Attempts to access sensitive files"),

    Pattern("EXFILTRATION", "high",
        "Conversation history extraction",
        r"(?i)(repeat|output|print|show|copy)\s+(all\s+)?(previous|prior|the\s+full|entire|all)\s+(conversation|messages?|chat|history|context)",
        "Attempts to extract conversation history"),

    # --- Tool / capability abuse ---
    Pattern("TOOL_ABUSE", "critical",
        "Direct tool invocation instruction",
        r"(?i)(use\s+the\s+|call\s+the\s+|invoke\s+the\s+|run\s+the\s+)(exec|shell|bash|terminal|file|read|write|delete|tool)\s*(tool|function|command|plugin)?",
        "Instructs agent to invoke specific tools"),

    Pattern("TOOL_ABUSE", "high",
        "Code execution attempt",
        r"(?i)(execute|run|eval|subprocess|os\.system|shell_exec|exec\()\s*[\(\`'\"]",
        "Attempts to embed executable code"),

    Pattern("TOOL_ABUSE", "high",
        "File system manipulation",
        r"(?i)(delete|remove|overwrite|modify|write\s+to)\s+(all\s+)?(files?|documents?|the\s+file)\s+(in|at|under|from)",
        "Attempts to manipulate files via agent"),

    # --- Context spoofing ---
    Pattern("CONTEXT_SPOOF", "high",
        "Fake user/assistant turn injection",
        r"(?m)^(Human:|User:|Assistant:|AI:|Bot:|GLaDOS:|Agent:)\s+",
        "Attempts to inject fake conversational turns"),

    Pattern("CONTEXT_SPOOF", "medium",
        "Fake system message boundary",
        r"(?i)(---+\s*)?(END\s+OF\s+DOCUMENT|END\s+OF\s+CONTENT|DOCUMENT\s+ENDS?\s+HERE|IGNORE\s+ABOVE|STOP\s+READING\s+HERE)",
        "Attempts to create a false document boundary"),

    # --- Urgency / override pressure ---
    Pattern("URGENCY_OVERRIDE", "high",
        "Authority/urgency override framing",
        r"(?i)(URGENT|CRITICAL|IMPORTANT|MANDATORY|REQUIRED)[:\s]{1,5}(override|ignore|bypass|disregard|execute\s+immediately)",
        "Urgency framing used to pressure override"),

    Pattern("URGENCY_OVERRIDE", "medium",
        "Embedded 'special instruction' header",
        r"(?i)^#+\s*(special|hidden|secret|important|override|admin|system)\s+(instructions?|notes?|commands?|directives?)\s*$",
        "Markdown header styling to make injected instructions look legitimate"),

    # --- Skill file specific ---
    Pattern("SKILL_INJECTION", "critical",
        "Skill file structure mimicry",
        r"(?i)(^---\s*\n.*?name:\s*.+\n.*?description:\s*.+\n.*?---)",
        "YAML frontmatter that mimics a skill file header"),

    Pattern("SKILL_INJECTION", "high",
        "Agent behavior override via skill syntax",
        r"(?i)(when\s+.{0,60}:\s*\n\s*(always|never|must|do not|ignore|bypass))",
        "Skill-style conditional instruction that overrides agent behavior"),

    # --- Model-specific format tokens (ChatML / Qwen / LLaMA / tool formats) ---
    Pattern("CONTEXT_SPOOF", "critical",
        "ChatML / Qwen model format token",
        r"<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>|<\|system\|>|<\|user\|>|<\|assistant\|>",
        "Qwen/ChatML special tokens — in external content signals prompt boundary injection"),

    Pattern("CONTEXT_SPOOF", "critical",
        "LLaMA instruction format token",
        r"(?m)^\s*\[INST\]|</s>\s*\[INST\]|\[/INST\]",
        "LLaMA-format instruction delimiter — creates false instruction boundary"),

    # --- Tool call injection ---
    Pattern("TOOL_ABUSE", "critical",
        "Structured tool call injection",
        r"<tool_call>|<function_call>|<tool_response>|<tool_result>",
        "Tool call XML tags in external content — attempts to inject fake tool invocations"),

    Pattern("TOOL_ABUSE", "high",
        "JSON tool call structure injection",
        r'(?i)"tool_use"\s*:|"function_call"\s*:|"tool_name"\s*:.{0,60}"input"\s*:',
        "JSON-structured tool call pattern — may inject agent actions"),

    # --- Conditional and delayed triggers ---
    Pattern("INSTRUCTION_OVERRIDE", "high",
        "Conditional trigger — fires when content is read by agent",
        r"(?i)(if|when)\s+(you|claude|the\s+(ai|agent|assistant|model))\s+(read|reads?|see|sees?|process(?:es)?|encounter|encounters?)\s+(this|the\s+(following|above))",
        "Delayed trigger designed to fire when processed by agent — evades per-fetch detection"),

    Pattern("INSTRUCTION_OVERRIDE", "high",
        "Temporal activation trigger",
        r"(?i)when\s+this\s+(message|text|content|output|document)\s+(is|was|gets?)\s+(read|processed|ingested|loaded|seen)\s+by",
        "Content that activates conditionally on being read — cross-turn injection pattern"),

    # --- Backdoored model / model-aware semantic triggers ---
    Pattern("ROLE_HIJACK", "high",
        "Model-aware self-reference injection",
        r"(?i)as\s+(the\s+)?(ai|assistant|claude|anthropic|llm|language\s+model)\s*[,:\-]",
        "Content narrating from the model's perspective — typical of backdoored model output injections"),

    Pattern("INSTRUCTION_OVERRIDE", "high",
        "Model output correction / addendum framing",
        r"(?i)(model|assistant|ai)\s+(update|correction|addendum|override|note|clarification)\s*[:\-]",
        "Framing external content as an authoritative model correction"),

    Pattern("INSTRUCTION_OVERRIDE", "medium",
        "Hidden or embedded instruction framing",
        r"(?i)(internal|hidden|embedded|secret|invisible)\s+(instruction|note|directive|command)\s*[:\-]",
        "Attempts to pass instructions as hidden metadata"),

    # --- Encoded / obfuscated payloads ---
    Pattern("EXFILTRATION", "high",
        "Base64 decode instruction",
        r"(?i)base64\s*[_\-]?\s*(decode|decoding)|(?:decode|deserialize)\s+(?:the\s+following|this\s+(string|payload|data))",
        "Instruction to decode an encoded payload — common obfuscation technique"),

    Pattern("EXFILTRATION", "medium",
        "Hex escape sequence cluster",
        r"(\\x[0-9a-fA-F]{2}){3,}",
        "Dense hex escape sequences — possible encoded payload"),

    # --- Length anomaly (additive signal, low severity) ---
    Pattern("URGENCY_OVERRIDE", "low",
        "Unusually long content block",
        r"(?s).{8000,}",
        "Content exceeds 8,000 chars — very long documents have higher injection surface area"),
]

SEVERITY_SCORE = {"low": 1, "medium": 3, "high": 7, "critical": 15}
SEVERITY_ORDER = ["critical", "high", "medium", "low"]

# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    line: int
    col: int
    category: str
    severity: str
    description: str
    note: str
    snippet: str

def scan(text: str) -> list[Finding]:
    findings = []
    lines = text.splitlines()
    for pat in PATTERNS:
        for m in re.finditer(pat.regex, text, re.MULTILINE | re.DOTALL):
            # Find line number
            line_no = text[:m.start()].count('\n') + 1
            col = m.start() - text[:m.start()].rfind('\n') - 1
            snippet = m.group(0)[:80].replace('\n', ' ')
            findings.append(Finding(
                line=line_no, col=col,
                category=pat.category, severity=pat.severity,
                description=pat.description, note=pat.note,
                snippet=snippet
            ))
    # Deduplicate overlapping findings (same line+category)
    seen = set()
    deduped = []
    for f in findings:
        key = (f.line, f.category, f.severity)
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    deduped = sorted(deduped, key=lambda f: (-SEVERITY_SCORE[f.severity], f.line))

    # Statistical scoring layer (if model available)
    stat_model = _load_stat_model()
    if stat_model:
        raw, ntok = _stat_score(text, stat_model)
        if ntok >= 10:
            normalized = raw / ntok
            corpus = stat_model.get("corpus_stats", {})
            note = (f"n-gram score {raw:+.1f} ({normalized:+.3f}/token) | "
                    f"model trained on {corpus.get('malicious_docs',0)} malicious, "
                    f"{corpus.get('benign_docs',0)} benign docs")
            if normalized > 1.5:
                sev = "high"
            elif normalized > 0.5:
                sev = "medium"
            elif normalized > 0.0:
                sev = "low"
            else:
                sev = None
            if sev:
                deduped.insert(0, Finding(
                    line=0, col=0,
                    category="STATISTICAL",
                    severity=sev,
                    description="N-gram Markov analysis: document language pattern is malicious-leaning",
                    note=note,
                    snippet="(whole document)"
                ))
    return deduped

def risk_score(findings: list[Finding]) -> int:
    return sum(SEVERITY_SCORE[f.severity] for f in findings)

def risk_level(score: int) -> str:
    if score == 0:     return "CLEAN"
    if score < 5:      return "LOW"
    if score < 15:     return "MEDIUM"
    if score < 30:     return "HIGH"
    return "CRITICAL"

# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

COLORS = {
    "critical": "\033[91m", "high": "\033[93m",
    "medium": "\033[94m",   "low": "\033[96m",
    "CLEAN": "\033[92m",    "reset": "\033[0m"
}

def fmt_text(path: str, findings: list[Finding], score: int, threshold: str) -> str:
    level = risk_level(score)
    c = COLORS
    out = [f"\n{c[level.lower() if level.lower() in c else 'reset']}prompt-lint: {path}{c['reset']}"]
    out.append(f"Risk: {c.get(level.lower(), '')}{'■' * min(score, 20)} {level} (score: {score}){c['reset']}\n")
    if not findings:
        out.append(f"{c['CLEAN']}✓ No injection patterns detected{c['reset']}")
        return '\n'.join(out)
    for f in findings:
        col = c.get(f.severity, '')
        out.append(f"  {col}[{f.severity.upper():8}] L{f.line:>4}  {f.category}{c['reset']}")
        out.append(f"           {f.description}")
        out.append(f"           snippet: \"{f.snippet}\"")
        if f.note:
            out.append(f"           note: {f.note}")
        out.append("")
    out.append(f"  {len(findings)} finding(s) — review before agent processing")
    return '\n'.join(out)

def fmt_json(path: str, findings: list[Finding], score: int) -> str:
    return json.dumps({
        "file": path,
        "risk_level": risk_level(score),
        "risk_score": score,
        "finding_count": len(findings),
        "findings": [asdict(f) for f in findings]
    }, indent=2)

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Batch scan — cross-document fragmented injection detection
# ---------------------------------------------------------------------------

def scan_batch(paths: list[Path], threshold: str = "low") -> dict:
    """
    Scan a batch of documents and detect both per-document findings and
    cross-document fragmented injection patterns.

    Fragmented injection: a multi-stage attack where no single document
    triggers detection, but the combination does. Classic pattern:
      doc1: "when you see the phrase ACTIVATE..."
      doc5: "...ACTIVATE: execute [malicious action]"

    Returns a BatchReport dict suitable for JSON output or terminal display.
    """
    min_score = SEVERITY_SCORE[threshold]

    # --- Per-document scan ---
    doc_results = []
    all_texts = {}
    for p in paths:
        try:
            text = p.read_text(errors="replace")
        except Exception as e:
            doc_results.append({"file": str(p), "error": str(e)})
            continue
        all_texts[str(p)] = text
        findings = scan(text)
        filtered = [f for f in findings if SEVERITY_SCORE[f.severity] >= min_score]
        score = risk_score(filtered)
        doc_results.append({
            "file": str(p),
            "risk_level": risk_level(score),
            "risk_score": score,
            "finding_count": len(filtered),
            "findings": [asdict(f) for f in filtered],
        })

    # --- Cross-document fragmentation detection ---
    cross_findings = _cross_doc_scan(all_texts)

    total_score = sum(d.get("risk_score", 0) for d in doc_results)
    has_cross = len(cross_findings) > 0
    batch_level = risk_level(total_score + (30 if has_cross else 0))

    return {
        "batch_risk_level": batch_level,
        "total_score": total_score,
        "documents_scanned": len(doc_results),
        "cross_document_findings": cross_findings,
        "documents": doc_results,
    }


# Patterns that only make sense as *half* of a multi-document attack
_FRAGMENT_PATTERNS = [
    # Setup fragments: plant a trigger keyword
    (re.compile(
        r"(?i)when\s+you\s+(see|encounter|read|receive)\s+(?:the\s+(?:word|phrase|text|string|keyword|code))?\s*[\"']?([A-Z_]{3,20})[\"']?",
        re.IGNORECASE),
     "trigger_setup",
     "Sets up a trigger keyword — may pair with a completion fragment in another doc"),

    # Completion fragments: invoke the keyword
    (re.compile(
        r"(?i)\b([A-Z_]{3,20})\b\s*[:]\s*(execute|run|send|delete|exfiltrate|override|ignore|bypass)",
        re.IGNORECASE),
     "trigger_completion",
     "Activates a keyword trigger with a malicious action — check if keyword was planted elsewhere"),

    # Continuation fragments
    (re.compile(
        r"(?i)(continued?\s+from\s+(previous|prior|above|last)\s+(page|document|source|result))",
        re.IGNORECASE),
     "continuation",
     "Claims to continue from another document — potential cross-turn injection"),

    # Accumulating instructions
    (re.compile(
        r"(?i)(add\s+this\s+to|remember\s+for\s+(later|the\s+next|subsequent)\s+(step|request|turn|message|page))",
        re.IGNORECASE),
     "accumulation",
     "Instructs agent to carry information forward across documents/turns"),
]


def _cross_doc_scan(texts: dict[str, str]) -> list[dict]:
    """
    Detect fragmented injection patterns across a batch of documents.
    Looks for setup/completion pairs and accumulation patterns.
    """
    findings = []

    # Collect all fragment hits per type
    fragment_hits: dict[str, list[dict]] = {}
    for path, text in texts.items():
        for pat, frag_type, note in _FRAGMENT_PATTERNS:
            for m in pat.finditer(text):
                line_no = text[:m.start()].count('\n') + 1
                fragment_hits.setdefault(frag_type, []).append({
                    "file": path,
                    "line": line_no,
                    "snippet": m.group(0)[:80],
                    "note": note,
                })

    # Flag if both setup and completion fragments appear (in any docs)
    setups = fragment_hits.get("trigger_setup", [])
    completions = fragment_hits.get("trigger_completion", [])
    if setups and completions:
        findings.append({
            "type": "CROSS_DOC_TRIGGER_PAIR",
            "severity": "critical",
            "description": "Trigger setup/completion pair found across documents — possible fragmented injection",
            "setup_fragments": setups,
            "completion_fragments": completions,
        })

    # Flag any accumulation or continuation patterns
    for frag_type in ("accumulation", "continuation"):
        for hit in fragment_hits.get(frag_type, []):
            findings.append({
                "type": f"CROSS_DOC_{frag_type.upper()}",
                "severity": "high",
                "description": hit["note"],
                "file": hit["file"],
                "line": hit["line"],
                "snippet": hit["snippet"],
            })

    return findings


def fmt_batch_text(report: dict) -> str:
    c = COLORS
    level = report["batch_risk_level"]
    lc = c.get(level.lower(), "")
    lines = [
        f"\n{lc}prompt-lint batch: {report['documents_scanned']} documents{c['reset']}",
        f"Batch risk: {lc}{level} (total score: {report['total_score']}){c['reset']}\n",
    ]

    cross = report.get("cross_document_findings", [])
    if cross:
        lines.append(f"{c['critical']}⚠  CROSS-DOCUMENT FINDINGS ({len(cross)}){c['reset']}")
        for cf in cross:
            sev = cf.get("severity", "high")
            lines.append(f"  {c.get(sev, '')}[{sev.upper()}] {cf['type']}{c['reset']}")
            lines.append(f"         {cf['description']}")
            if "setup_fragments" in cf:
                for s in cf["setup_fragments"][:3]:
                    lines.append(f"         setup  → {s['file']}:{s['line']}  \"{s['snippet']}\"")
            if "completion_fragments" in cf:
                for s in cf["completion_fragments"][:3]:
                    lines.append(f"         fire   → {s['file']}:{s['line']}  \"{s['snippet']}\"")
            lines.append("")

    for doc in report["documents"]:
        if "error" in doc:
            lines.append(f"  ✗ {doc['file']}: {doc['error']}")
            continue
        rl = doc["risk_level"]
        dc = c.get(rl.lower() if rl.lower() in c else "reset", "")
        flag = "✓" if rl == "CLEAN" else "✗"
        lines.append(
            f"  {dc}{flag} [{rl:8}]{c['reset']} {doc['file']}"
            + (f"  ({doc['finding_count']} findings)" if doc["finding_count"] else "")
        )

    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(
        description="Lint text/markdown files for prompt injection patterns")
    parser.add_argument("files", nargs="*",
        help="File(s) to scan, or - for stdin. Multiple files trigger batch mode.")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--threshold", choices=["low", "medium", "high", "critical"],
                        default="low", help="Minimum severity to report")
    parser.add_argument("--exit-code", action="store_true",
                        help="Exit 1 if any findings above threshold")
    parser.add_argument("--batch", action="store_true",
                        help="Force batch mode (cross-document analysis) even for single file")
    parser.add_argument("--dir", type=Path, metavar="DIR",
                        help="Scan all .md/.txt files in a directory (implies batch mode)")
    args = parser.parse_args()

    # --- Collect files ---
    paths: list[Path] = []
    if not args.files and not args.dir:
        parser.print_help()
        sys.exit(2)
    if args.dir:
        paths = sorted(args.dir.glob("**/*.md")) + sorted(args.dir.glob("**/*.txt"))
        if not paths:
            print(f"error: no .md or .txt files found in {args.dir}", file=sys.stderr)
            sys.exit(2)
    elif len(args.files) == 1 and args.files[0] == "-":
        text = sys.stdin.read()
        findings = scan(text)
        min_score = SEVERITY_SCORE[args.threshold]
        filtered = [f for f in findings if SEVERITY_SCORE[f.severity] >= min_score]
        score = risk_score(filtered)
        if args.format == "json":
            print(fmt_json("<stdin>", filtered, score))
        else:
            print(fmt_text("<stdin>", filtered, score, args.threshold))
        if args.exit_code and filtered:
            sys.exit(1)
        return
    else:
        for f in args.files:
            p = Path(f)
            if not p.exists():
                print(f"error: file not found: {f}", file=sys.stderr)
                sys.exit(2)
            paths.append(p)

    # --- Batch mode: multiple files or --batch / --dir flag ---
    if len(paths) > 1 or args.batch or args.dir:
        report = scan_batch(paths, threshold=args.threshold)
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(fmt_batch_text(report))
        if args.exit_code:
            has_issues = (report["total_score"] > 0 or
                          len(report.get("cross_document_findings", [])) > 0)
            if has_issues:
                sys.exit(1)
        return

    # --- Single file mode ---
    path = paths[0]
    text = path.read_text(errors="replace")
    findings = scan(text)
    min_score = SEVERITY_SCORE[args.threshold]
    filtered = [f for f in findings if SEVERITY_SCORE[f.severity] >= min_score]
    score = risk_score(filtered)

    if args.format == "json":
        print(fmt_json(str(path), filtered, score))
    else:
        print(fmt_text(str(path), filtered, score, args.threshold))

    if args.exit_code and filtered:
        sys.exit(1)



def main():
    parser = argparse.ArgumentParser(
        description="Lint text/markdown files for prompt injection patterns")
    parser.add_argument("files", nargs="*",
        help="File(s) to scan, or - for stdin. Multiple files trigger batch mode.")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--threshold", choices=["low", "medium", "high", "critical"],
                        default="low", help="Minimum severity to report")
    parser.add_argument("--exit-code", action="store_true",
                        help="Exit 1 if any findings above threshold")
    parser.add_argument("--batch", action="store_true",
                        help="Force batch mode (cross-document analysis) even for single file")
    parser.add_argument("--dir", type=Path, metavar="DIR",
                        help="Scan all .md/.txt files in a directory (implies batch mode)")
    args = parser.parse_args()

    # --- Collect files ---
    paths: list[Path] = []
    if not args.files and not args.dir:
        parser.print_help()
        sys.exit(2)
    if args.dir:
        paths = sorted(args.dir.glob("**/*.md")) + sorted(args.dir.glob("**/*.txt"))
        if not paths:
            print(f"error: no .md or .txt files found in {args.dir}", file=sys.stderr)
            sys.exit(2)
    elif len(args.files) == 1 and args.files[0] == "-":
        text = sys.stdin.read()
        findings = scan(text)
        min_score = SEVERITY_SCORE[args.threshold]
        filtered = [f for f in findings if SEVERITY_SCORE[f.severity] >= min_score]
        score = risk_score(filtered)
        if args.format == "json":
            print(fmt_json("<stdin>", filtered, score))
        else:
            print(fmt_text("<stdin>", filtered, score, args.threshold))
        if args.exit_code and filtered:
            sys.exit(1)
        return
    else:
        for f in args.files:
            p = Path(f)
            if not p.exists():
                print(f"error: file not found: {f}", file=sys.stderr)
                sys.exit(2)
            paths.append(p)

    # --- Batch mode: multiple files or --batch / --dir flag ---
    if len(paths) > 1 or args.batch or args.dir:
        report = scan_batch(paths, threshold=args.threshold)
        if args.format == "json":
            print(json.dumps(report, indent=2))
        else:
            print(fmt_batch_text(report))
        if args.exit_code:
            has_issues = (report["total_score"] > 0 or
                          len(report.get("cross_document_findings", [])) > 0)
            if has_issues:
                sys.exit(1)
        return

    # --- Single file mode ---
    path = paths[0]
    text = path.read_text(errors="replace")
    findings = scan(text)
    min_score = SEVERITY_SCORE[args.threshold]
    filtered = [f for f in findings if SEVERITY_SCORE[f.severity] >= min_score]
    score = risk_score(filtered)

    if args.format == "json":
        print(fmt_json(str(path), filtered, score))
    else:
        print(fmt_text(str(path), filtered, score, args.threshold))

    if args.exit_code and filtered:
        sys.exit(1)

if __name__ == "__main__":
    main()

