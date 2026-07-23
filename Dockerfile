# agent-guard — the MCP safety-check server over HTTP (/mcp).
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY agent_guard ./agent_guard
RUN pip install --no-cache-dir ".[mcp]" uvicorn

EXPOSE 8080
# Public HTTP deployment: AGENT_GUARD_HTTP=1 drops scan_project (a local filesystem tool) from the tool set,
# leaving only the pure, input-bounded checks. See agent_guard/mcp_server.py.
ENV AGENT_GUARD_HTTP=1
# Bind to the host's $PORT when set (Render/Fly assign it), else 8080. Shell form so $PORT expands.
CMD ["sh", "-c", "uvicorn agent_guard.asgi:app --host 0.0.0.0 --port ${PORT:-8080}"]
