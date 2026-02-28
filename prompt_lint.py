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

def main():
    parser = argparse.ArgumentParser(
        description="Lint text/markdown files for prompt injection patterns")
    parser.add_argument("file", help="File to scan, or - for stdin")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    parser.add_argument("--threshold", choices=["low", "medium", "high", "critical"],
                        default="low", help="Minimum severity to report")
    parser.add_argument("--exit-code", action="store_true",
                        help="Exit 1 if any findings above threshold")
    args = parser.parse_args()

    if args.file == "-":
        text = sys.stdin.read()
        path = "<stdin>"
    else:
        p = Path(args.file)
        if not p.exists():
            print(f"error: file not found: {args.file}", file=sys.stderr)
            sys.exit(2)
        text = p.read_text(errors="replace")
        path = str(p)

    findings = scan(text)
    # Filter by threshold
    min_score = SEVERITY_SCORE[args.threshold]
    filtered = [f for f in findings if SEVERITY_SCORE[f.severity] >= min_score]
    score = risk_score(filtered)

    if args.format == "json":
        print(fmt_json(path, filtered, score))
    else:
        print(fmt_text(path, filtered, score, args.threshold))

    if args.exit_code and filtered:
        sys.exit(1)

if __name__ == "__main__":
    main()
