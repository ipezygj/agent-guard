# agent-guard

**The safety check an AI agent runs *before* it acts.**

Every agent that installs packages, runs shell commands, or commits/outputs text can do real
damage: install malware, wipe a disk, or leak a credential. `agent-guard` is three cheap,
dependency-free checks — the "look before you leap" gate an agent (or you) calls before the
irreversible step.

```bash
pip install agent-tripwire            # the checks (zero deps)
pip install "agent-tripwire[mcp]"     # + the MCP server for agents
```

## Use it as an MCP tool (for agents)

An agent can call these itself before acting. Add to your MCP client (Claude/Cursor/Claude Code):

```json
{ "mcpServers": { "agent-guard": { "command": "agent-guard-mcp" } } }
```

<sub>MCP registry identity — `mcp-name: io.github.ipezygj/agent-guard`</sub>

| tool | the agent calls it before… |
|---|---|
| `check_package` | `pip/npm install` — is it real, malware, a typosquat, or does it run code on install? |
| `check_command` | running a shell command — is it a destructive / remote-code-exec vector (rm -rf, curl\|bash, dd, force-push)? |
| `scan_secrets` | committing / pasting / logging — does the text leak an API key, token, or private key? |

## The three checks

**check_package** — existence on the registry (a hallucinated name is a red flag), typosquat
distance to popular packages, npm install/postinstall scripts (the classic supply-chain malware
vector), and OSV malware/vulnerability advisories. Mainstream packages pass; look-alikes and
install-time-code flag.

**check_command** — matches destructive / RCE shell patterns with a severity and a plain reason.
`rm -rf /`, `curl … | bash`, `dd of=/dev/sda`, fork bombs → critical; force-push, hard-reset,
`sudo`, `DROP TABLE` → high.

**scan_secrets** — AWS/OpenAI/Anthropic/Google/Stripe/GitHub/Slack keys, private-key blocks, JWTs,
and generic `api_key=`/`password=` assignments. Returns each finding (type, line, redacted).

```python
from agent_guard import analyze_command, scan_secrets, check_package
analyze_command("rm -rf /")["danger"]           # "critical"
scan_secrets("token = 'ghp_...'")["leaked"]     # True
check_package("reqwests", "pypi")["risk"]       # "high" (typosquat of requests)
```

The point: an agent about to install/run/commit should check first — and now it can, in one call,
with a plain verdict and a recommendation. If a check comes back high/critical, stop and get a human.

## License
MIT
