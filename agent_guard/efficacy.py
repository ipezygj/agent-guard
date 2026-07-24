#!/usr/bin/env python3
"""efficacy — a MACHINE-READABLE proof manifest, so an agent (not just a human) can see the evidence.

The benchmark numbers are credibility for humans deciding to adopt. But an autonomous agent choosing a
guard at runtime reads TOOL METADATA, not a blog post. This emits the measured efficacy as a compact JSON
an agent (or a registry) can fetch and reason over: what classes are covered (mapped to OWASP LLM Top 10
+ MITRE ATLAS), the measured hold/recall/false-positive rates, the named limits, and the provenance of
each number. Regenerate with `python -m agent_guard.efficacy` (writes efficacy.json next to the package).

Every number here is produced by re-running the harnesses, not hand-typed — so the manifest can't drift
from what the tests actually measure.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import bench, redteam, corpus_external


def manifest() -> dict:
    b = bench.run(verbose=False)
    r = redteam.run(verbose=False)
    e = corpus_external.run(verbose=False)
    return {
        "tool": "agent-guard (behavioural layer)",
        "claim": "Catches cross-call exfiltration chains, prompt-injection consequences, and "
                 "unauthorized side-effect tool calls in an AI agent's action trace.",
        "measured": {
            "labeled_corpus": {
                "recall_on_modeled_patterns": b["recall_modeled"],
                "recall_overall_incl_evasions": b["recall"],
                "false_positive_rate": b["fp_rate"],
                "provenance": "self-authored (honest: includes deliberate evasions + FP traps)",
            },
            "adversarial_redteam": {
                "generated_variants": r["total"],
                "hold_rate_on_observable_signal": r["hold"],
                "unexpected_bypasses": r["bypass"],
                "false_positives_under_mutation": r["fp"],
                "provenance": "generator (mutation swarm) — ports the audit arsenal's red-team discipline",
            },
            "external_taxonomy_corpus": {
                "in_scope_classes_caught": f"{e['caught']}/{e['in_scope']}",
                "recall": e["recall"],
                "standard": ["OWASP Top 10 for LLM Applications 2025",
                             "MITRE ATLAS (AML.T0051 + Exfiltration via AI Agent Tool Invocation)"],
                "provenance": "attack shapes defined by an EXTERNAL authority, not the tool's author",
            },
        },
        "covers": {
            "OWASP LLM01:2025": "Prompt Injection (direct + indirect) → consequence detection",
            "OWASP LLM02:2025": "Sensitive Information Disclosure → cross-call exfiltration chain",
            "OWASP LLM06:2025": "Excessive Agency → side-effect tool call after untrusted content",
            "MITRE AML.T0051": "LLM Prompt Injection",
            "MITRE ATLAS": "Exfiltration via AI Agent Tool Invocation",
        },
        "out_of_scope_by_design": {
            "OWASP LLM07:2025": "System Prompt Leakage — a model-OUTPUT property, not in the action trace",
            "OWASP LLM04/LLM08/LLM09/LLM10": "poisoning / embeddings / misinformation / DoS — not action-level",
            "OWASP LLM03:2025": "Supply Chain — handled by a different agent-guard tool (check_package)",
        },
        "named_limits": [
            "Exfiltration to an ALLOWLISTED host — host-allowlisting cannot distinguish it from legit traffic.",
            "A secret referenced through an unresolvable shell VARIABLE — a trace-level guard never sees it.",
        ],
        "verifiable_proof": "Every guarded run can emit an Ed25519-signed receipt (guard_receipt) that "
                            "anyone verifies with only the public key — proof the guard ran and its verdict.",
        "reproduce": "python -m agent_guard.bench ; python -m agent_guard.redteam ; "
                     "python -m agent_guard.corpus_external  (all locked as regression-gate tests)",
    }


def write(path: str | None = None) -> str:
    p = Path(path or (Path(__file__).parent / "efficacy.json"))
    p.write_text(json.dumps(manifest(), indent=2), encoding="utf-8")
    return str(p)


if __name__ == "__main__":
    import sys
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    out = write()
    print(f"wrote {out}")
    print(json.dumps(manifest()["measured"], indent=2))
