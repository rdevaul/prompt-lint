# Skill Trust and Prompt Injection: A Position Paper

**Authors:** Richard W. DeVaul  
**Date:** February 2026  
**Status:** Draft v0.1

---

## Abstract

As LLM-based agents are increasingly delegated to perform research, automation,
and multi-step tasks, the question of which instructions they should follow
becomes a first-order security concern. We argue that the dominant framing —
detecting *malicious* prompts — is the wrong level of abstraction. The correct
frame is *provenance*: an agent should only execute skills and instructions that
have been explicitly allowlisted and, ideally, cryptographically verified. All
other instruction-like content encountered during task execution should be
treated as untrusted input, regardless of apparent intent. We describe the
threat model, the correct architectural response, and two complementary tools:
`prompt-lint`, a presence-based injection detector, and a proposed skill signing
framework.

---

## 1. The Wrong Question

The instinctive response to prompt injection is to ask: *is this prompt
malicious?* This frames the problem as an intent-classification task —
distinguishing "bad" instructions from "good" ones. This framing is
fundamentally flawed for at least three reasons.

**Intent is unverifiable.** A document containing agent instructions may have
been written by a researcher sharing a workflow, a developer documenting a
skill, or an attacker crafting an injection payload. The text itself cannot
tell you which. Any classifier trained to distinguish "malicious" from "benign"
instructions is solving a problem that doesn't have a reliable ground truth.

**Benign intent does not imply safe execution.** A legitimately written skill
file encountered in fetched web content is just as dangerous to an unhardened
sub-agent as a deliberately malicious one. If the agent executes it, the
effect is the same: unexpected behavior driven by instructions outside the
agent's sanctioned scope.

**The attack surface is the intersection, not the instruction.** The vulnerability
is not that an attacker wrote bad instructions — it is that a sub-agent was
positioned to encounter and act on instructions it was never meant to receive.
The correct intervention is architectural, not classificatory.

---

## 2. The Correct Frame: Provenance and Allowlisting

The correct question is not "is this instruction malicious?" but "was this
instruction given to this agent by an authorized source?"

An agent operating on a research task has a defined set of capabilities and
a defined set of instructions. Those instructions come from:

1. The agent's system prompt (set by the operator)
2. Skills explicitly loaded at initialization (loaded by the operator)
3. The user's message (from a trusted user)

Everything else — web pages, documents, tool outputs, API responses, file
contents, email bodies — is **data**, not instructions. An agent that treats
data as instructions is vulnerable by construction, regardless of how benign
the data appears.

### 2.1 The Skill Allowlist

Skills are a particular concern because they are the mechanism by which agent
behavior is extended. An agent framework that loads skills discovered at
runtime (from web content, from fetched files, from user-provided documents)
has eliminated the operator's ability to control agent behavior.

The correct architecture is a **strict allowlist**: the set of skills
available to an agent is fixed at initialization and cannot be extended by
anything the agent encounters during task execution. If a skill is not on
the allowlist, it is not executed — full stop.

This is a departure from the convenient but dangerous pattern of "the agent
can discover and load new skills from the web." That pattern is exactly the
attack surface that prompt injection exploits. Skill discovery must happen
out-of-band, through a human-reviewed process, before an agent is deployed
on a task.

### 2.2 Cryptographic Skill Verification

An allowlist of skill names is necessary but not sufficient. A skill file
can be modified between when it was reviewed and when it is loaded. An
attacker who can modify a skill file on disk, in a package repository, or
in transit can inject malicious behavior through an allowlisted skill.

The complete solution requires **cryptographic verification of skill integrity
and provenance**:

- Each skill is signed by its author (Ed25519 or equivalent)
- The operator maintains a trust store of authorized signing keys
- At load time, each skill's signature is verified against the trust store
- A skill that fails signature verification is not loaded, even if its name
  is on the allowlist

This is analogous to how package managers like apt and npm handle package
signing, or how iOS handles code signing. The key insight is that trust is
transitive from the signing key: if you trust the author's key, you trust
any skill they sign, subject to review.

**The proposed skill signing workflow:**

```
Author writes SKILL.md
    ↓
Author signs: skill-sign SKILL.md --key author.pem → SKILL.md.sig
    ↓
Operator reviews SKILL.md + verifies signature
    ↓
Operator adds author's public key to trust store
    ↓
Agent runtime verifies signature at load time
    ↓
Unsigned or unverified skills: rejected
```

This chain ensures that a skill executed by an agent has been:
1. Written by a known, trusted author (key in trust store)
2. Reviewed by the operator (review is the gate to adding a key)
3. Unchanged since review (signature would fail if modified)

---

## 3. Prompt-Lint: Detection as a Defense-in-Depth Layer

The architectural solution (allowlisting + signing) is the correct long-term
answer. But many current agent deployments do not yet have this infrastructure.
In the interim — and as a defense-in-depth layer even when allowlisting is in
place — content scanning provides a practical first line of defense.

`prompt-lint` (https://github.com/rdevaul/prompt-lint) implements **presence
detection**: scanning external content for instruction-like patterns before a
sub-agent processes it. The critical design choice is that it detects
*presence* of injection-like content, not *intent*.

**What it detects:**
- Instruction overrides ("ignore previous instructions")
- Role hijack patterns ("you are now X")
- Permission escalation claims ("you have been granted")
- Exfiltration attempts (requests for system prompts, credentials)
- Tool abuse (embedded exec/shell invocations)
- Context spoofing (fake conversation turns)
- Skill injection (skill file syntax in external content)
- Urgency override framing ("IMPORTANT: disregard...")

**What it does not claim to detect:** novel, obfuscated, or purely semantic
injections. It is not a complete solution. Its role is to catch the common
case — the known patterns that appear in the wild — with zero external
dependencies and sub-millisecond latency, suitable for inline pipeline use.

### 3.1 Recommended Pipeline Integration

```
External content (web, email, file, API response)
    ↓
prompt-lint --threshold high --exit-code
    ↓ (if CLEAN or LOW)
Pass to sub-agent for processing
    ↓ (if HIGH or CRITICAL)
Quarantine: summarize only, do not pass raw content to agent
```

The threshold setting matters. `--threshold high` is recommended for
production pipelines: it reduces false positives at the cost of missing
subtle injections. `--threshold low` for high-security contexts where
false positives are acceptable.

### 3.2 Statistical Layer

In addition to rule-based patterns, prompt-lint includes an n-gram LLR
statistical model trained on a corpus of benign and malicious documents.
The statistical score provides signal on content that pattern-matches don't
cover — unusual token distributions characteristic of injection attempts.
The model is retrained incrementally as the corpus grows.

---

## 4. The Layered Defense Model

No single mechanism is sufficient. The correct architecture combines:

| Layer | Mechanism | What it prevents |
|-------|-----------|-----------------|
| Architectural | Strict skill allowlist | Agent loading unauthorized skills |
| Cryptographic | Skill signing + trust store | Tampered or impersonated skills |
| Runtime | Prompt-lint content scanning | Known injection patterns in fetched content |
| Process | Human review gate for allowlist | Unreviewed skills entering the allowlist |
| Monitoring | Behavior anomaly detection | Novel attacks that evade other layers |

Each layer has failure modes. An allowlist can become stale; a signing key
can be compromised; pattern detection can be evaded. Defense in depth means
that an attacker must defeat multiple independent layers simultaneously.

---

## 5. Implications for Agentic Framework Design

Current agentic frameworks vary widely in their handling of skill trust. Many
frameworks support dynamic skill loading from arbitrary sources. We argue this
is a design defect, not a feature.

**Recommendations for framework designers:**

1. **Separate skill discovery from skill execution.** Discovery (finding new
   skills) should be a human-mediated, out-of-band process. Execution (using
   skills) should be limited to the approved list.

2. **Provide a native signing and verification mechanism.** Skill authors
   should have a standard way to sign their work; operators should have a
   standard way to verify it. This should be a first-class framework feature,
   not an afterthought.

3. **Default to deny.** A sub-agent encountering a skill file it wasn't given
   should reject it silently, not execute it. The default should be the secure
   behavior.

4. **Treat all external content as data.** Web pages, documents, API responses,
   and tool outputs are data. They should be processed (read, summarized,
   extracted from) but never used as a source of executable instructions.

5. **Surface the trust model to operators.** Operators deploying agents on
   sensitive tasks need visibility into which skills are loaded, who signed
   them, and when they were reviewed. This should be auditable.

---

## 6. Conclusion

The prompt injection problem is not fundamentally a classification problem —
it is a trust boundary problem. The correct solution is not a better classifier
for malicious intent; it is a rigorous architecture that prevents untrusted
instructions from reaching an agent in the first place.

prompt-lint provides practical detection for the current state of deployments.
The skill signing framework provides the longer-term architectural answer. Used
together as part of a layered defense model, they significantly raise the cost
of a successful prompt injection attack against an agentic research pipeline.

The tools are available and the pattern is clear. What remains is adoption.

---

## References

- Greshake et al. (2023). "Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection." *arXiv:2302.12173*
- Perez & Ribeiro (2022). "Ignore Previous Prompt: Attack Techniques for Language Models." *NeurIPS ML Safety Workshop*
- Boucher et al. (2021). "Bad Characters: Imperceptible NLP Attacks." *arXiv:2106.09898*
- prompt-lint: https://github.com/rdevaul/prompt-lint
- OpenClaw skill framework: https://docs.openclaw.ai/skills

---

*Feedback welcome. This is a working draft — the skill signing specification
in particular will be developed further as implementation begins.*
