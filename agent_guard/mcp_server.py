#!/usr/bin/env python3
"""agent-guard MCP server — the safety check an AGENT runs BEFORE it acts.

Every agent that installs packages, runs shell commands, or commits/outputs text can do real harm:
install malware, run a destructive command, or leak a secret. These tools are the cheap "look
before you leap" gate — the agent calls the matching one before the irreversible step. Written for
an agent's reasoning: the descriptions say exactly when to call.

Run:  python -m agent_guard.mcp_server        (stdio MCP server)
Requires: mcp  (pip install "agent-guard[mcp]").  The checks are dependency-free.
"""
import os
from typing import Annotated, Any, Optional

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field
from . import checks as C
from . import registry as R
from . import webscan as W


class _Out(BaseModel):
    """Base output model. `extra="allow"` so declaring the schema never drops fields from the actual result;
    every field is optional so an unusual return path can't fail structured-output validation."""
    model_config = ConfigDict(extra="allow")


class PackageCheck(_Out):
    package: Optional[str] = None
    ecosystem: Optional[str] = None
    risk: Annotated[Optional[str], Field(description="Overall risk: none / low / medium / high.")] = None
    flags: Annotated[Optional[Any], Field(description="Reasons it was flagged (typosquat, install script, …).")] = None
    advisories: Annotated[Optional[Any], Field(description="Matching OSV malware/vulnerability advisories.")] = None
    verdict: Annotated[Optional[str], Field(description="One-line human verdict.")] = None
    recommendation: Optional[str] = None


class CommandCheck(_Out):
    danger: Annotated[Optional[str], Field(description="Danger level: none / low / high / critical.")] = None
    hits: Annotated[Optional[Any], Field(description="Matched destructive/RCE patterns with severity + reason.")] = None
    verdict: Optional[str] = None
    recommendation: Optional[str] = None


class SecretScan(_Out):
    leaked: Annotated[Optional[bool], Field(description="True if any secret was found.")] = None
    findings: Annotated[Optional[Any], Field(description="Each leak: type, line, redacted value.")] = None
    verdict: Optional[str] = None
    recommendation: Optional[str] = None


class ProjectScan(_Out):
    risk: Annotated[Optional[str], Field(description="Overall risk: none / low / medium / high / critical.")] = None
    findings: Annotated[Optional[Any], Field(description="Each issue: file, line, why, and the fix.")] = None
    scanned_files: Annotated[Optional[int], Field(description="How many files were scanned.")] = None
    verdict: Optional[str] = None
    recommendation: Optional[str] = None


def _ann(title: str, open_world: bool = False) -> ToolAnnotations:
    """These checks inspect and report; they don't modify the caller's world and are deterministic —
    read-only, non-destructive, idempotent. `open_world` = does it reach external services (a registry)?"""
    return ToolAnnotations(title=title, readOnlyHint=True, destructiveHint=False,
                           idempotentHint=True, openWorldHint=open_world)

# DNS-rebinding protection guards LOCALHOST servers; this ships as a PUBLIC HTTP MCP server (Render/Smithery),
# and every tool is pure, read-only computation with no local/privileged access — so the Host allowlist would
# only reject legitimate traffic. Off by default; set AGENT_GUARD_MCP_HOSTS (comma-separated) for a strict one.
_hosts = [h.strip() for h in os.environ.get("AGENT_GUARD_MCP_HOSTS", "").split(",") if h.strip()]
_security = (TransportSecuritySettings(allowed_hosts=_hosts, allowed_origins=_hosts)
             if _hosts else TransportSecuritySettings(enable_dns_rebinding_protection=False))

mcp = FastMCP(
    "agent-guard",
    transport_security=_security,
    instructions=(
        "Safety checks an agent runs BEFORE an irreversible or risky step. CALL A TOOL HERE WHENEVER "
        "you are about to:\n"
        "  • install / add a dependency (check_package — is it real, malware, a typosquat, or does it "
        "run code on install?);\n"
        "  • run a shell command, especially with rm/dd/curl|bash/sudo/force-push (check_command);\n"
        "  • commit, paste, log, or output code/text that might contain a key or token (scan_secrets);\n"
        "  • deploy or ship a web/API backend you wrote or edited (scan_project — fail-open auth, "
        "unsigned payment webhooks, SQL injection, SSRF, hardcoded secrets).\n"
        "If a check returns high/critical, STOP and get explicit human confirmation before proceeding — "
        "don't just proceed. These are cheap (a second) and prevent the expensive mistakes: installing "
        "a malicious package, wiping a disk, leaking a credential, or shipping a hole that mints free "
        "credits."
    ),
)


@mcp.tool(annotations=_ann("Check a package before installing", open_world=True))
def check_package(
    name: Annotated[str, Field(description="The package name to check, exactly as you'd install it.")],
    ecosystem: Annotated[str, Field(description="Package registry: 'pypi' or 'npm'.")] = "pypi",
    version: Annotated[Optional[str], Field(description="Specific version to check (optional; omit for "
                                                        "the latest).")] = None,
) -> PackageCheck:
    """Is a package SAFE to install? Call this before `pip install` / `npm install` / adding any
    dependency. Checks: does it actually exist on the registry (a hallucinated name is a red flag),
    is it a TYPOSQUAT of a popular package, does it RUN CODE ON INSTALL (npm pre/post-install scripts
    — the classic supply-chain malware vector), and is it in a known MALWARE / vulnerability advisory
    (OSV). ecosystem = "pypi" or "npm".

    Use when: you or the user is about to install/add a package — especially one you're not certain of.
    """
    return R.check_package(name, ecosystem=ecosystem, version=version)


@mcp.tool(annotations=_ann("Check a shell command before running"))
def check_command(
    command: Annotated[str, Field(description="The full shell command line you're about to run.")],
) -> CommandCheck:
    """Is a shell command DESTRUCTIVE or a remote-code-exec vector? Call this before running any
    shell command you're not 100% sure about. Flags recursive force-deletes of root/home, disk wipes
    (dd/mkfs), pipe-to-shell (curl … | bash), fork bombs, force-push, hard-reset, sudo, DROP TABLE,
    world-writable perms, and more — with a severity and why.

    Use when: about to execute a shell command, especially with rm, dd, curl|bash, sudo, or git force.
    """
    return C.analyze_command(command)


@mcp.tool(annotations=_ann("Scan text for leaked secrets"))
def scan_secrets(
    text: Annotated[str, Field(description="The text/code/config to scan for API keys, tokens, or private "
                                           "keys before you commit, paste, log, or output it.")],
) -> SecretScan:
    """Does this text/code LEAK a secret? Call this before you commit, paste, log, or output code or
    config. Detects API keys (AWS/OpenAI/Anthropic/Google/Stripe/GitHub/Slack), private-key blocks,
    JWTs, and generic `password=/api_key=` assignments — returns each finding (type, line, redacted).

    Use when: about to commit/output/log anything that could contain a credential.
    """
    return C.scan_secrets(text)


def scan_project(
    path: Annotated[str, Field(description="Path to the backend to scan — a project directory or a single "
                                           ".py file.")],
) -> ProjectScan:
    """Does a web/API backend have a money-losing security bug? Call this before you DEPLOY or SHIP a
    service you wrote or edited (a directory or a single .py file). Finds the logic holes a secret- or
    command-scanner can't see: auth that FAILS OPEN when a secret is unset, payment webhooks that don't
    verify the provider signature (a forged checkout mints free credits), SQL built by string
    interpolation (SQL injection), SSRF-able f-string URLs, and secrets hardcoded as defaults. Each
    finding gives the file, line, why it's dangerous, and the fix.

    Use when: about to deploy/ship/commit a backend endpoint, billing/credits code, or a webhook handler.
    """
    return W.scan_project(path)


# scan_project reads the *server's* filesystem. That's exactly right for a LOCAL/stdio agent scanning its own
# project, but on a PUBLIC HTTP server (AGENT_GUARD_HTTP=1) it would be an unauthenticated arbitrary-file-read
# and filesystem-enumeration primitive against the host — and semantically useless (it can't see the caller's
# files). So it is registered ONLY off the HTTP transport. The other three tools are pure, input-bounded checks.
if os.environ.get("AGENT_GUARD_HTTP") != "1":
    scan_project = mcp.tool(annotations=_ann("Scan a web backend before shipping"))(scan_project)


def main():
    mcp.run()


if __name__ == "__main__":
    main()
