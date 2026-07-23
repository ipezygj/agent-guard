#!/usr/bin/env python3
"""Registry checks for check_package — the network signal a typosquat heuristic can't give:
does the package exist, how new is it, does it run code on install (npm scripts — the classic
supply-chain / Lazarus-style malware vector), and is it in a known-vulnerability / malware advisory
(OSV). Stdlib urllib only; every call is best-effort (returns a note on failure, never crashes).
"""
import json
import urllib.request, urllib.parse, urllib.error
from .checks import typosquat_check

_UA = {"User-Agent": "agent-guard", "Accept": "application/json"}


def _get(url, timeout=12):
    try:
        req = urllib.request.Request(url, headers=_UA)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r), r.status
    except urllib.error.HTTPError as e:
        return None, e.code
    except Exception:
        return None, None


def _post(url, body, timeout=12):
    try:
        req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                     headers={**_UA, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r), r.status
    except Exception:
        return None, None


def _pypi(name):
    d, code = _get(f"https://pypi.org/pypi/{name}/json")
    if not d:
        return {"exists": code != 404, "reachable": code is not None}
    releases = d.get("releases", {})
    dates = [f["upload_time"] for v in releases.values() for f in v if f.get("upload_time")]
    return {"exists": True, "reachable": True, "n_releases": len(releases),
            "first_release": min(dates) if dates else None,
            "scripts": False, "summary": (d.get("info", {}).get("summary") or "")[:120]}


def _npm(name):
    d, code = _get(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@/')}")
    if not d:
        return {"exists": code != 404, "reachable": code is not None}
    times = d.get("time", {})
    latest = (d.get("dist-tags", {}) or {}).get("latest")
    ver = (d.get("versions", {}) or {}).get(latest, {})
    scripts = ver.get("scripts", {}) or {}
    install_hooks = {k: v for k, v in scripts.items() if k in ("preinstall", "install", "postinstall")}
    return {"exists": True, "reachable": True, "n_releases": len(d.get("versions", {})),
            "first_release": times.get("created"), "latest": latest,
            "scripts": bool(install_hooks), "install_hooks": install_hooks}


def _osv(name, ecosystem):
    eco = {"pypi": "PyPI", "npm": "npm"}.get(ecosystem, ecosystem)
    d, _ = _post("https://api.osv.dev/v1/query", {"package": {"name": name, "ecosystem": eco}})
    if not d:
        return []
    out = []
    for v in d.get("vulns", []):
        out.append({"id": v.get("id"), "summary": (v.get("summary") or "")[:140],
                    "malware": "malware" in (v.get("summary", "") + str(v.get("id", ""))).lower()})
    return out


def check_package(name: str, ecosystem: str = "pypi", version: str = None) -> dict:
    """Combine typosquat + registry + OSV into one verdict for a package the agent is about to install."""
    flags = []
    ts = typosquat_check(name, ecosystem)
    if ts.get("typosquat"):
        flags.append(("HIGH", f"Typosquat: {ts['verdict']}"))

    meta = _npm(name) if ecosystem == "npm" else _pypi(name)
    if meta.get("reachable") is False:
        flags.append(("INFO", "Registry unreachable — couldn't verify existence/age/scripts."))
    elif not meta.get("exists"):
        flags.append(("HIGH", f"'{name}' is NOT on {ecosystem} — cannot verify; a hallucinated or "
                              "not-yet-published name (do not install)."))
    else:
        if meta.get("scripts"):
            flags.append(("HIGH", f"Runs code on install ({', '.join(meta.get('install_hooks', {}))}) — "
                                  "the classic supply-chain execution vector. Inspect those scripts."))
        if meta.get("n_releases", 99) <= 2 and meta.get("first_release"):
            flags.append(("MEDIUM", f"Very new / few releases (first: {meta['first_release'][:10]}) — "
                                    "unusual for a dependency you'd trust; extra caution if it mimics a popular name."))

    advisories = _osv(name, ecosystem)
    malware = [a for a in advisories if a["malware"]]
    vulns = [a for a in advisories if not a["malware"]]
    for a in malware:
        flags.append(("CRITICAL", f"OSV MALWARE advisory {a['id']}: {a['summary']}"))
    if vulns:
        # historical CVEs are usually fixed in newer versions — informational, not a block-install
        # (a mainstream package shouldn't read as 'high risk' just for having a security history)
        flags.append(("INFO", f"{len(vulns)} security advisory(ies) on record — usually fixed in newer "
                              f"versions; install a current/patched version (e.g. {vulns[0]['id']})."))

    order = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "INFO": 0}
    worst = max((order[s] for s, _ in flags), default=-1)
    level = {3: "critical", 2: "high", 1: "medium", 0: "info", -1: "clear"}[worst]
    return {
        "package": name, "ecosystem": ecosystem, "risk": level,
        "flags": [f"[{s}] {m}" for s, m in flags],
        "meta": {k: meta.get(k) for k in ("exists", "n_releases", "first_release", "scripts", "summary")},
        "advisories": advisories,
        "verdict": ("No red flags found — still confirm the publisher is who you expect."
                    if level in ("clear", "info") else
                    f"{level.upper()} risk: " + flags[[order[s] for s, _ in flags].index(worst)][1]),
        "recommendation": ("Safe to install (verify publisher)." if level in ("clear", "info") else
                           "Do NOT install without a human confirming this is the intended package."),
    }


if __name__ == "__main__":
    import sys
    n = sys.argv[1] if len(sys.argv) > 1 else "requests"
    eco = sys.argv[2] if len(sys.argv) > 2 else "pypi"
    print(json.dumps(check_package(n, eco), indent=2)[:800])
