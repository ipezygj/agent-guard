"""asgi — the agent-guard MCP server over streamable-HTTP, for a hosted deployment.

Serves the MCP server at `/mcp` (so agents and registries like Smithery can reach it by URL, not only over
stdio via pip) plus a plain `/health` for the host's health check. The tools are identical to the stdio server.

Run:  uvicorn agent_guard.asgi:app --host 0.0.0.0 --port $PORT
"""
from __future__ import annotations

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from .mcp_server import mcp

_mcp_app = mcp.streamable_http_app()          # a Starlette app serving /mcp, with its own session lifespan


async def health(request):
    return JSONResponse({"ok": True, "service": "agent-guard"})


app = Starlette(
    routes=[Route("/health", health)] + list(_mcp_app.routes),
    lifespan=lambda a: _mcp_app.router.lifespan_context(a),
)
