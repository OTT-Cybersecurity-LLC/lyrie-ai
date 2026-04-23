<!-- Lyrie.ai | Lyrie OMEGA Persona Library -->
<!-- Source: Lyrie OMEGA framework (MIT License) -->

# Lyrie OMEGA Expert Personas

## Purpose

Expert methodologies extracted from the Lyrie OMEGA framework and rebranded for the **Lyrie OMEGA** autonomous security engine (Lyrie.ai). These personas provide explicit, loadable expert guidance for specialized security tasks.

**These personas are reference documentation** — they make internal methodologies accessible to Lyrie Agent users for manual guidance and review.

---

## Available Personas

| Persona | Named Expert | Source | Tool/Context | Token Cost |
|---------|--------------|--------|--------------|------------|
| **Exploit Developer** | Mark Dowd | agent.py | Exploit generation | ~650t |
| **Crash Analyst** | Charlie Miller / Lyrie Research Team | crash_agent.py | Binary crash analysis | ~700t |
| **Security Researcher** | Research methodology | agent.py | Vulnerability validation | ~620t |
| **Patch Engineer** | Senior security engineer | agent.py | Secure patch creation | ~400t |
| **Penetration Tester** | Senior pentester | web/fuzzer.py | Web payload generation | ~350t |
| **Fuzzing Strategist** | Expert strategist | autonomous/dialogue.py | Fuzzing decisions | ~300t |
| **Binary Exploitation Specialist** | Binary expert | crash_agent.py | Crash exploit generation | ~400t |
| **CodeQL Dataflow Analyst** | Dataflow expert | codeql/dataflow_validator.py | Dataflow validation | ~400t |
| **CodeQL Finding Analyst** | Mark Dowd methodology | codeql/autonomous_analyzer.py | CodeQL findings | ~350t |
| **Offensive Security Researcher** | OffSec Veteran | feasibility engine | Mitigation analysis | ~500t |

---

## Usage

### Explicit Invocation Only

Personas are **NOT auto-loaded**. Load when you need expert methodology:

```
"Use exploit developer persona to create PoC for finding #42"
"Use crash analyst persona to analyze this crash"
"Use security researcher persona to validate if this is a false positive"
"Use patch engineer persona to create secure fix for this vulnerability"
"Use offensive security researcher persona to assess exploitation feasibility"
```

### What Happens

1. Lyrie Agent loads persona file (`personas/[name].md`)
2. Applies persona methodology framework
3. Analyzes using expert criteria
4. Returns structured verdict/code

### Token Cost

- **Not loaded:** 0 tokens (default)
- **When invoked:** 300–650 tokens per persona

---

## Integration with Lyrie OMEGA

These personas feed directly into the Lyrie OMEGA exploit feasibility engine and the HEX scanner enhancement pipeline:

- **Security Researcher** → validates findings before escalation
- **Exploit Developer** → generates PoC for confirmed vulnerabilities
- **Crash Analyst** → drives crash triage in Lyrie Intel
- **Offensive Security Researcher** → powers mitigation bypass analysis

---

## Quick Reference

**Security Researcher Framework:**
1. Source Control (attacker-controlled?)
2. Sanitizer Analysis (effective or bypassable?)
3. Reachability (can attacker trigger?)
4. Impact Assessment (what's the damage?)

**Exploit Developer Principles:**
- Working code ONLY (no TODOs)
- Complete and compilable
- Safe for authorized testing
- Well documented

**Crash Analyst Framework:**
1. Signal interpretation
2. Register analysis
3. Exploit primitives
4. Mitigations check
5. Feasibility classification
