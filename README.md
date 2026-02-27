# prompt-lint

A fast, dependency-free prompt injection detector for agentic research pipelines.

Scans text and markdown files for patterns that suggest prompt injection attempts,
agent skill hijacking, permission escalation, exfiltration, and other attacks
targeting LLM-based agents.

## Why

Sub-agents delegated to research tasks are often less hardened against prompt injection
than a primary assistant. A quick lint pass on fetched content before an agent processes
it provides a lightweight but meaningful safety layer.

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

## Contributing

### Adding patterns

Patterns live in the `PATTERNS` list in `prompt_lint.py`. Each pattern needs:
- `category` — one of the categories above
- `severity` — `low | medium | high | critical`
- `description` — one-line human description
- `regex` — the detection pattern
- `note` — explanation of the attack vector

### Test suite

The `tests/` directory contains labeled examples:
- `tests/benign/` — legitimate documentation, READMEs, research notes
- `tests/malicious/` — known injection payloads (labeled by category/source)
- `tests/ambiguous/` — skill files, agent docs, borderline content

Run tests: `python3 tests/run_tests.py`

## Limitations

- Pattern-based; a sufficiently novel/obfuscated attack may evade detection
- Does not detect semantic injection (paraphrased attacks without keywords)
- Unicode homoglyphs, Base64 encoding, and split-token attacks not yet covered
- High threshold mode may miss subtle attacks; low threshold has more false positives

## License

MIT
