"""Every MCP tool must be findable in the README.

Third repo to get this, and the sweep that prompted it is the point: numguard had
eleven tools listed nowhere, evalgate had two. This one has three tools and all
were already documented — which is why the check is worth running rather than
assuming.

The decorator here carries arguments (`@mcp.tool(annotations=_ann(...))`). A
pattern like `@mcp.tool\([^)]*\)` stops at the first paren inside `_ann(...)`
and matches nothing, which is how an earlier sweep printed "0 tools, none
undocumented" and looked like an all-clear.
"""
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SERVER = ROOT / "agent_guard" / "mcp_server.py"
README = ROOT / "README.md"


def _tools():
    src = SERVER.read_text(encoding="utf-8")
    found = []
    for chunk in src.split("@mcp.tool")[1:]:
        m = re.search(r"\ndef (\w+)\(", chunk)
        if m:
            found.append(m.group(1))
    return sorted(set(found))


def test_the_parser_finds_tools_at_all():
    """Guards the guard: a parser that matches nothing passes every test below."""
    assert len(_tools()) >= 3, f"only {len(_tools())} tools found — decorator shape changed?"


@pytest.mark.parametrize("tool", _tools())
def test_tool_is_named_in_the_readme(tool):
    assert tool in README.read_text(encoding="utf-8"), (
        f"MCP tool {tool} appears nowhere in README.md — an agent choosing a tool reads that, "
        "so an unlisted tool is an uncallable one"
    )
