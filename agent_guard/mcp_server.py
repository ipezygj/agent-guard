#!/usr/bin/env python3
"""agent-guard MCP server — the safety check an AGENT runs BEFORE it acts.

Every agent that installs packages, runs shell commands, or commits/outputs text can do real harm:
install malware, run a destructive command, or leak a secret. These tools are the cheap "look
before you leap" gate — the agent calls the matching one before the irreversible step. Written for
an agent's reasoning: the descriptions say exactly when to call.

Run:  python -m agent_guard.mcp_server        (stdio MCP server)
Requires: mcp  (pip install "agent-guard[mcp]").  The checks are dependency-free.
"""
from mcp.server.fastmcp import FastMCP
from . import checks as C
from . import registry as R

mcp = FastMCP(
    "agent-guard",
    instructions=(
        "Safety checks an agent runs BEFORE an irreversible or risky step. CALL A TOOL HERE WHENEVER "
        "you are about to:\n"
        "  • install / add a dependency (check_package — is it real, malware, a typosquat, or does it "
        "run code on install?);\n"
        "  • run a shell command, especially with rm/dd/curl|bash/sudo/force-push (check_command);\n"
        "  • commit, paste, log, or output code/text that might contain a key or token (scan_secrets).\n"
        "If a check returns high/critical, STOP and get explicit human confirmation before proceeding — "
        "don't just proceed. These are cheap (a second) and prevent the expensive mistakes: installing "
        "a malicious package, wiping a disk, or leaking a credential."
    ),
)


@mcp.tool()
def check_package(name: str, ecosystem: str = "pypi", version: str = None) -> dict:
    """Is a package SAFE to install? Call this before `pip install` / `npm install` / adding any
    dependency. Checks: does it actually exist on the registry (a hallucinated name is a red flag),
    is it a TYPOSQUAT of a popular package, does it RUN CODE ON INSTALL (npm pre/post-install scripts
    — the classic supply-chain malware vector), and is it in a known MALWARE / vulnerability advisory
    (OSV). ecosystem = "pypi" or "npm".

    Use when: you or the user is about to install/add a package — especially one you're not certain of.
    """
    return R.check_package(name, ecosystem=ecosystem, version=version)


@mcp.tool()
def check_command(command: str) -> dict:
    """Is a shell command DESTRUCTIVE or a remote-code-exec vector? Call this before running any
    shell command you're not 100% sure about. Flags recursive force-deletes of root/home, disk wipes
    (dd/mkfs), pipe-to-shell (curl … | bash), fork bombs, force-push, hard-reset, sudo, DROP TABLE,
    world-writable perms, and more — with a severity and why.

    Use when: about to execute a shell command, especially with rm, dd, curl|bash, sudo, or git force.
    """
    return C.analyze_command(command)


@mcp.tool()
def scan_secrets(text: str) -> dict:
    """Does this text/code LEAK a secret? Call this before you commit, paste, log, or output code or
    config. Detects API keys (AWS/OpenAI/Anthropic/Google/Stripe/GitHub/Slack), private-key blocks,
    JWTs, and generic `password=/api_key=` assignments — returns each finding (type, line, redacted).

    Use when: about to commit/output/log anything that could contain a credential.
    """
    return C.scan_secrets(text)


def main():
    mcp.run()


if __name__ == "__main__":
    main()
