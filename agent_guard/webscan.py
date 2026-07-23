#!/usr/bin/env python3
"""agent-guard project scanner — the security review an AGENT runs BEFORE it ships a web/API backend.

An agent that writes or edits a service (FastAPI/Flask billing, a credits ledger, a payment webhook,
an internal admin endpoint) can leave a hole that costs real money: auth that fails OPEN when a
secret is unset, a payment webhook that never checks the signature (forged checkout -> free credits),
SQL built by string interpolation, an SSRF-able f-string URL, or a credential hardcoded as a default.
These are logic bugs a secret-scanner or a command-checker never sees. `scan_project(path)` reads the
Python sources and reports them with a severity, the exact line, why it's dangerous, and the fix.

Offline, deterministic, dependency-free (stdlib regex). Every finding points to the pattern it matched
— no false authority.
"""
import re
from pathlib import Path

_SECRET_WORD = r'(?:SECRET|API[_-]?KEY|TOKEN|PASSWORD|PRIVATE[_-]?KEY|WEBHOOK)'

# secret vars read from env with an EMPTY default (the ones a fail-open check keys on)
# NOTE: every variable-length class below is BOUNDED ({0,N}) not unbounded (*) — an unbounded
# `[^"']*`/`[^\n]*` that can fail late backtracks O(n²) on one long line and DoSes the scanner
# (a crafted source file would hang it). Bounds keep every regex effectively linear.
_ENV_SECRET = re.compile(rf'(\w{{0,40}}{_SECRET_WORD}\w{{0,40}})\s*=\s*os\.environ\.get\(\s*["\'][^"\']{{0,200}}["\']\s*(?:,\s*["\']["\']\s*)?\)', re.I)
# secret read from env with a NON-EMPTY hardcoded default = a real fallback credential in the source
_INSECURE_DEFAULT = re.compile(rf'os\.environ\.get\(\s*["\'][^"\']{{0,80}}{_SECRET_WORD}[^"\']{{0,80}}["\']\s*,\s*["\']([^"\']{{6,200}})["\']\s*\)', re.I)
# `if SECRET and <cmp>` — enforcement gated on the secret being set (fails OPEN when unset)
_FAIL_OPEN = re.compile(r'\bif\s+(?:not\s+)?(\w+)\s+and\b[^\n:]{0,200}(?:!=|==)', re.I)
# fetch primitive with an f-string URL that interpolates a variable
_SSRF = re.compile(r'\b(?:urlopen|urlretrieve|Request|requests\.(?:get|post|put|delete)|httpx\.(?:get|post|put))\s*\(\s*f["\']https?://[^"\']{0,300}\{', re.I)
# SQL built by interpolation rather than parameterized
_SQL = re.compile(r'\.execute(?:script)?\s*\(\s*(?:f["\']|["\'][^"\']{0,300}["\']\s*%|["\'][^"\']{0,300}["\']\s*\+|["\'][^"\']{0,300}\{[^}]{1,200}\})', re.I)
# a secret-named var interpolated into a returned / raised / logged string
_SECRET_LEAK = re.compile(rf'(?:return|raise|HTTPException|log(?:ger)?\.\w+|print)\b[^\n]{{0,300}}f["\'][^"\']{{0,200}}\{{[^}}]{{0,200}}{_SECRET_WORD}[^}}]{{0,200}}\}}', re.I)

_SEV = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}


def _line(src, off):
    return src.count("\n", 0, off) + 1


def _funcs(src):
    """crude (name, body, start_offset) per def, so webhook checks are function-scoped."""
    out = []
    for m in re.finditer(r'^(?:async\s+)?def\s+(\w+)\s*\(', src, re.M):
        start = m.start()
        nxt = re.search(r'^(?:async\s+)?def\s', src[m.end():], re.M)
        end = m.end() + nxt.start() if nxt else len(src)
        out.append((m.group(1), src[start:end], start))
    return out


_MAX_SRC = 400_000   # cap scanned bytes per file — real source is far smaller; caps regex work


def _scan_src(src, fn):
    src = src[:_MAX_SRC]
    out = []
    env_secrets = {m.group(1) for m in _ENV_SECRET.finditer(src)}

    for m in _FAIL_OPEN.finditer(src):
        if m.group(1) in env_secrets:
            out.append(dict(severity="HIGH", type="fail-open-auth", file=fn, line=_line(src, m.start()),
                            why=f"auth is gated on `{m.group(1)} and ...` — when {m.group(1)} is unset (its "
                                f"default), the check is SKIPPED and the endpoint is open to anyone.",
                            fix=f"fail CLOSED: `if not {m.group(1)} or hdr != {m.group(1)}: reject`."))

    for m in _INSECURE_DEFAULT.finditer(src):
        out.append(dict(severity="HIGH", type="insecure-default-secret", file=fn, line=_line(src, m.start()),
                        why=f"a secret has a hardcoded fallback ('{m.group(1)[:6]}…') — anyone reading the "
                            f"source knows it; it ships as a real credential.",
                        fix="require the env var; refuse to start / reject the request if it is unset."))

    for name, body, start in _funcs(src):
        if "webhook" in name.lower() or "webhook" in body[:200].lower():
            parses = re.search(r'json\.loads\(\s*(?:payload|body|await|request|data)', body)
            verifies = re.search(r'construct_event|verify_(?:signature|header)|hmac\.|compare_digest|check_signature', body)
            if parses and not verifies:
                out.append(dict(severity="CRITICAL", type="webhook-no-verify", file=fn, line=_line(src, start),
                                why=f"webhook handler `{name}` parses the request body without verifying a "
                                    f"signature — anyone can forge an event (e.g. a paid-checkout → free credits).",
                                fix="verify the provider signature (stripe.Webhook.construct_event / HMAC) and "
                                    "fail CLOSED if the signing secret is unset."))
            elif verifies and parses:
                # a verify path exists but so does an unsigned json.loads fallback. If that fallback is
                # already behind a fail-closed raise (explicit opt-in), it's safe — don't flag.
                window = body[max(0, parses.start() - 240):parses.start()]
                if not re.search(r'\b(?:raise|abort)\b|HTTPException\s*\(', window):
                    out.append(dict(severity="CRITICAL", type="webhook-fail-open", file=fn, line=_line(src, start),
                                    why=f"webhook handler `{name}` verifies the signature only conditionally — it "
                                        f"has an unsigned `json.loads(payload)` fallback (fires when the signing "
                                        f"secret is unset), so a forged event still mints credits/grants.",
                                    fix="remove the unsigned fallback; if the signing secret is unset, REJECT."))

    for m in _SSRF.finditer(src):
        out.append(dict(severity="HIGH", type="ssrf-fstring-url", file=fn, line=_line(src, m.start()),
                        why="a fetched URL is built from an f-string with an interpolated variable — an "
                            "attacker-influenced value can redirect the request (SSRF / path traversal).",
                        fix="validate the value against a strict allow-list / charset before building the URL."))

    for m in _SQL.finditer(src):
        out.append(dict(severity="CRITICAL", type="sql-string-build", file=fn, line=_line(src, m.start()),
                        why="SQL is built by string interpolation (f-string / % / +) — SQL injection.",
                        fix="use parameterized queries: execute(sql, (args,))."))

    for m in _SECRET_LEAK.finditer(src):
        out.append(dict(severity="MEDIUM", type="secret-in-response", file=fn, line=_line(src, m.start()),
                        why="a secret-named variable is interpolated into a returned / raised / logged string — "
                            "it may leak the credential to a caller or a log sink.",
                        fix="never echo secrets; return a generic message."))
    return out


def scan_project(path: str, max_files: int = 400) -> dict:
    """Scan a Python web/API project (a directory or a single .py file) for money-backend security
    bugs a secret/command scanner can't see. Returns findings + a verdict + a recommendation."""
    p = Path(path or ".").expanduser()
    if not p.exists():
        return {"risk": "invalid", "findings": [], "verdict": f"Path not found: {path}",
                "recommendation": "Point scan_project at a real file or directory."}
    if p.is_file():
        files = [p]
    else:
        files = []
        for f in p.rglob("*.py"):        # stream + stop at the cap — never materialize the whole tree
            s = str(f)
            if ("test" in f.name.lower() or "site-packages" in s
                    or ".venv" in s or "node_modules" in s):
                continue
            files.append(f)
            if len(files) >= max_files:
                break
    findings = []
    for f in files:
        try:
            if not f.is_file() or f.is_symlink():   # skip symlinks / non-regular (device/fifo) files
                continue
            with f.open("rb") as fh:                # bounded read — never load a huge file into memory
                src = fh.read(_MAX_SRC).decode("utf-8", errors="ignore")
        except Exception:
            continue
        rel = str(f.relative_to(p)) if p.is_dir() else str(f)
        findings.extend(_scan_src(src, rel))
    findings.sort(key=lambda c: -_SEV.get(c["severity"], 0))
    if not findings:
        return {"risk": "clear", "findings": [], "scanned_files": len(files),
                "verdict": "No web money-backend bug pattern matched. Still review auth/scoping yourself.",
                "recommendation": "Nothing flagged on this axis — safe to proceed with a normal review."}
    worst = max(_SEV.get(c["severity"], 0) for c in findings)
    level = {3: "critical", 2: "high", 1: "medium"}[worst]
    top = findings[0]
    return {"risk": level, "findings": findings, "count": len(findings), "scanned_files": len(files),
            "verdict": f"{top['severity']}: {top['type']} in {top['file']}:{top['line']} — {top['why']}",
            "recommendation": ("STOP — do NOT deploy/ship this until the CRITICAL/HIGH findings are fixed; get a "
                               "human to confirm each fix." if level in ("critical", "high") else
                               "Review each finding before shipping.")}


if __name__ == "__main__":
    import sys, json
    if len(sys.argv) > 1 and sys.argv[1] != "--selftest":
        print(json.dumps(scan_project(sys.argv[1]), indent=2)[:2000])
    else:
        from agent_guard._selftest_webscan import run
        run()
