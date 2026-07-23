# agent-guard — the MCP safety-check server over HTTP (/mcp).
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY agent_guard ./agent_guard
RUN pip install --no-cache-dir ".[mcp]" uvicorn

EXPOSE 8080
# Bind to the host's $PORT when set (Render/Fly assign it), else 8080. Shell form so $PORT expands.
CMD ["sh", "-c", "uvicorn agent_guard.asgi:app --host 0.0.0.0 --port ${PORT:-8080}"]
