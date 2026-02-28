# prompt-lint

A fast, dependency-free prompt injection and skill presence detector for agentic pipelines.

## Intent — What This Is For

**prompt-lint is not primarily about detecting malicious intent.** A document
can be completely benign in motivation and still pose an injection risk to a
sub-agent that processes it.

The core threat model: a research sub-agent fetching content from the web,
email, documents, or tool outputs may encounter text that contains agent
instructions, skill-file syntax, or behavioral overrides — whether placed
there maliciously or not. An unhardened agent that processes this content
without filtering may execute those instructions.

**The correct defense is not intent detection — it is presence detection.**
Any skill or instruction set that the agent wasn't explicitly given should
be treated as a potential injection, regardless of whether it looks
"malicious." The only skills an agent should execute are those on a
pre-approved allowlist, ideally with cryptographic verification of their
integrity and provenance. Everything else — however innocent it may appear —
should be quarantined before reaching the agent.

prompt-lint implements the detection side of this: scanning external content
for the *presence* of instruction-like patterns before a sub-agent sees them.

## Why

Sub-agents delegated to research tasks are typically less hardened against
prompt injection than a primary assistant. They may have access to tools,
credentials, or actions that an attacker could exploit by embedding
instructions in fetched content.

A lint pass on external content before an agent processes it is a lightweight
but meaningful safety layer. It is not a complete solution — cryptographic
skill verification and strict allowlisting are also required — but it is a
practical first line of defense deployable today.

## Usage

```bash
# Scan a file
python3 prompt_lint.py suspicious_page.md

# Scan stdin
cat fetched_content.md | python3 prompt_lint.py -

# JSON output for pipeline integration
python3 prompt_lint.py page.md --format json

# Only report high/critical findings (lower false positives)
python3 prompt_lint.py page.md --threshold high

# Exit code 1 if flagged (for shell pipelines)
python3 prompt_lint.py page.md --threshold high --exit-code
```

## Risk Levels

| Score | Level    | Recommended action |
|-------|----------|--------------------|
| 0     | CLEAN    | Safe to process    |
| 1–4   | LOW      | Review if sensitive context |
| 5–14  | MEDIUM   | Summarize rather than pass raw to agent |
| 15–29 | HIGH     | Quarantine; human review recommended |
| 30+   | CRITICAL | Block; likely active injection attempt |

## Detection Categories

| Category              | Examples |
|-----------------------|----------|
| `INSTRUCTION_OVERRIDE`| "Ignore previous instructions", system prompt replacement |
| `ROLE_HIJACK`         | "You are now DAN", persona replacement, jailbreak patterns |
| `PERMISSION_ESCALATION` | Claimed grants, "developer mode", safety-disable claims |
| `EXFILTRATION`        | System prompt extraction, file/credential leaks |
| `TOOL_ABUSE`          | Direct tool invocation, embedded code execution |
| `CONTEXT_SPOOF`       | Fake Human:/Assistant: turns, false document boundaries |
| `URGENCY_OVERRIDE`    | IMPORTANT: override framing, hidden instruction headers |
| `SKILL_INJECTION`     | Skill file mimicry, agent behavior override via skill syntax |

## Pipeline Integration

```python
import subprocess, json

def lint_before_processing(filepath: str, threshold: str = "high") -> dict:
    result = subprocess.run(
        ["python3", "/path/to/prompt_lint.py", filepath,
         "--format", "json", "--threshold", threshold],
        capture_output=True, text=True
    )
    report = json.loads(result.stdout)
    if report["risk_level"] in ("HIGH", "CRITICAL"):
        # Quarantine: summarize instead of passing raw content to agent
        raise ValueError(f"Injection risk {report['risk_level']} in {filepath}")
    return report
```

## Statistical Layer

In addition to pattern matching, prompt-lint includes a statistical scoring
layer (n-gram LLR model) trained on a corpus of 11 malicious and 161 benign
documents. The statistical score is additive — it complements rule-based
findings without replacing them.

Retrain the model after expanding the corpus:
```bash
python3 corpus_analysis.py --output model.json
```

## Limitations

- Pattern-based; a sufficiently novel or obfuscated attack may evade detection
- Does not detect purely semantic injection (paraphrased attacks without keywords)
- Unicode homoglyphs, Base64 encoding, and split-token attacks not yet covered
- Not a substitute for allowlisting and cryptographic skill verification

## Related Work

See [`POSITION.md`](POSITION.md) for a broader treatment of the skill trust
problem: how skills should be allowlisted, cryptographically verified, and
isolated, and how prompt-lint fits into that security model.

## Contributing

Patterns live in the `PATTERNS` list in `prompt_lint.py`. The test suite is in
`tests/` with labeled benign, malicious, and ambiguous examples.

Run tests: `python3 tests/run_tests.py`

## License

MIT
