#!/usr/bin/env python3
"""Selftest for webscan — the vuln/safe FIXTURES live HERE, not in webscan.py, on purpose: the
fixtures literally contain the patterns webscan flags, so keeping them in the importable module made
`scan_project` flag its own source. This file's name contains "test", so scan_project skips it (its
directory walk excludes `*test*` files), and running the tool on the agent-guard repo stays clean."""
from pathlib import Path
from .webscan import scan_project

_VULN = '''
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

_SAFE = '''
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


def run():
    import tempfile
    d = Path(tempfile.mkdtemp())
    (d / "vuln.py").write_text(_VULN, encoding="utf-8")
    (d / "safe.py").write_text(_SAFE, encoding="utf-8")
    v = scan_project(str(d / "vuln.py"))
    s = scan_project(str(d / "safe.py"))
    types = {f["type"] for f in v["findings"]}
    expect = {"fail-open-auth", "webhook-no-verify", "insecure-default-secret", "sql-string-build", "ssrf-fstring-url"}
    assert expect <= types, f"missing: {expect - types}"
    assert v["risk"] == "critical"
    assert s["risk"] == "clear" and not s["findings"], f"false positive on safe: {s['findings']}"
    # ReDoS guard: a crafted 200k single-line source must not hang the scanner (bounded regexes)
    import time
    big = "X_SECRET = os.environ.get(" + "a" * 200_000
    t0 = time.perf_counter()
    scan_project.__globals__["_scan_src"](big, "big.py")
    assert time.perf_counter() - t0 < 2.0, "ReDoS: scan too slow on a long line"
    print("agent-guard webscan selftest: OK")


if __name__ == "__main__":
    run()
