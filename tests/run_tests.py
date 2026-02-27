#!/usr/bin/env python3
"""Run labeled test cases and report pass/fail."""
import subprocess, json, sys
from pathlib import Path

EXPECTED = {
    "benign": ("CLEAN", "LOW"),
    "malicious": ("HIGH", "CRITICAL"),
    "ambiguous": None,  # just print, no pass/fail
}

passed = failed = 0
for category, expected_levels in EXPECTED.items():
    test_dir = Path(__file__).parent / category
    if not test_dir.exists():
        continue
    for f in sorted(test_dir.glob("*.md")):
        result = subprocess.run(
            ["python3", str(Path(__file__).parent.parent / "prompt_lint.py"),
             str(f), "--format", "json", "--threshold", "low"],
            capture_output=True, text=True)
        try:
            d = json.loads(result.stdout)
        except Exception:
            print(f"PARSE ERROR: {f.name}")
            continue
        level = d["risk_level"]
        score = d["risk_score"]
        if expected_levels is None:
            print(f"  INFO  [{category}/{f.name}] → {level} (score: {score})")
        elif level in expected_levels:
            print(f"  PASS  [{category}/{f.name}] → {level} (score: {score})")
            passed += 1
        else:
            print(f"  FAIL  [{category}/{f.name}] → {level} (score: {score}), expected {expected_levels}")
            failed += 1

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
