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
_ENV_SECRET = re.compile(rf'(\w*{_SECRET_WORD}\w*)\s*=\s*os\.environ\.get\(\s*["\'][^"\']*["\']\s*(?:,\s*["\']["\']\s*)?\)', re.I)
# secret read from env with a NON-EMPTY hardcoded default = a real fallback credential in the source
_INSECURE_DEFAULT = re.compile(rf'os\.environ\.get\(\s*["\'][^"\']*{_SECRET_WORD}[^"\']*["\']\s*,\s*["\']([^"\']{{6,}})["\']\s*\)', re.I)
# `if SECRET and <cmp>` — enforcement gated on the secret being set (fails OPEN when unset)
_FAIL_OPEN = re.compile(r'\bif\s+(?:not\s+)?(\w+)\s+and\b[^\n:]*(?:!=|==)', re.I)
# fetch primitive with an f-string URL that interpolates a variable
_SSRF = re.compile(r'\b(?:urlopen|urlretrieve|Request|requests\.(?:get|post|put|delete)|httpx\.(?:get|post|put))\s*\(\s*f["\']https?://[^"\']*\{', re.I)
# SQL built by interpolation rather than parameterized
_SQL = re.compile(r'\.execute(?:script)?\s*\(\s*(?:f["\']|["\'][^"\']*["\']\s*%|["\'][^"\']*["\']\s*\+|["\'][^"\']*\{[^}]+\})', re.I)
# a secret-named var interpolated into a returned / raised / logged string
_SECRET_LEAK = re.compile(rf'(?:return|raise|HTTPException|log(?:ger)?\.\w+|print)\b[^\n]*f["\'][^"\']*\{{[^}}]*{_SECRET_WORD}[^}}]*\}}', re.I)

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


def _scan_src(src, fn):
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
        files = [f for f in p.rglob("*.py")
                 if "test" not in f.name.lower() and "site-packages" not in str(f)
                 and ".venv" not in str(f) and "node_modules" not in str(f)][:max_files]
    findings = []
    for f in files:
        try:
            src = f.read_text(encoding="utf-8", errors="ignore")
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


def _selftest():
    vuln = '''
import os
INTERNAL_SECRET = os.environ.get("INTERNAL_SECRET", "")
API_TOKEN = os.environ.get("API_TOKEN", "s3cr3t-default")
def deduct(request, key):
    if INTERNAL_SECRET and request.headers.get("x") != INTERNAL_SECRET:
        raise Exception("no")
    conn.execute(f"SELECT * FROM k WHERE key='{key}'")
async def stripe_webhook(request):
    payload = await request.body()
    event = json.loads(payload)
    add_credits(event["key"], event["credits"])
def fetch(name):
    return urlopen(f"https://pypi.org/pypi/{name}/json")
'''
    safe = '''
import os, stripe
INTERNAL_SECRET = os.environ.get("INTERNAL_SECRET", "")
def deduct(request, key):
    if not INTERNAL_SECRET or request.headers.get("x") != INTERNAL_SECRET:
        raise Exception("no")
    conn.execute("SELECT * FROM k WHERE key=?", (key,))
async def stripe_webhook(request):
    payload = await request.body()
    event = stripe.Webhook.construct_event(payload, sig, WEBHOOK_SECRET)
    add_credits(event["key"], event["credits"])
'''
    import tempfile
    d = Path(tempfile.mkdtemp())
    (d / "vuln.py").write_text(vuln, encoding="utf-8")
    (d / "safe.py").write_text(safe, encoding="utf-8")
    v = scan_project(str(d / "vuln.py"))
    s = scan_project(str(d / "safe.py"))
    types = {f["type"] for f in v["findings"]}
    expect = {"fail-open-auth", "webhook-no-verify", "insecure-default-secret", "sql-string-build", "ssrf-fstring-url"}
    assert expect <= types, f"missing: {expect - types}"
    assert v["risk"] == "critical"
    assert s["risk"] == "clear" and not s["findings"], f"false positive on safe: {s['findings']}"
    print("agent-guard webscan selftest: OK")


if __name__ == "__main__":
    import sys, json
    if len(sys.argv) > 1 and sys.argv[1] != "--selftest":
        print(json.dumps(scan_project(sys.argv[1]), indent=2)[:2000])
    else:
        _selftest()
