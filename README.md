# google-workspace-fast-mcp

Native Python/FastMCP implementation of the Google Workspace MCP server.

## Runtime model

- Tool surface is loaded from `tool_manifest_google.json` (parity names + input schemas)
- Tool execution is handled directly in Python via Google APIs
- Credential files are read from `GOOGLE_MCP_CREDENTIALS_DIR` or `~/.google_workspace_mcp/credentials`
- Supports legacy encrypted credential payloads (`MASTER_KEY`) from the upstream runtime

## Project configuration (`fastmcp.json`)

This repository now includes a canonical `fastmcp.json` aligned with FastMCP project configuration docs:

- `source`: `server.py:mcp`
- `environment`: uv-managed Python environment from local `pyproject.toml`
- `deployment`: HTTP runtime defaults (`/mcp`) plus runtime env wiring

FastMCP CLI arguments still override config values when needed.

## Runtime env

- Required:
  - Valid per-user credential files for tool calls (`user_google_email` argument)
  - `MASTER_KEY` when credential files are stored in legacy encrypted format

- Optional:
  - `GOOGLE_WORKSPACE_MCP_API_KEY` / `MCP_API_KEY` / `MCP_API_KEYS` for HTTP bearer auth
  - `GOOGLE_MCP_CREDENTIALS_DIR` custom credential path
  - `GOOGLE_OAUTH_CLIENT_ID` / `GOOGLE_OAUTH_CLIENT_SECRET` fallback OAuth client settings
  - `BASE_URL` (if needed for token verifier metadata)

## Validate and run

```bash
# Validate tool discovery / entrypoint
fastmcp inspect fastmcp.json
fastmcp inspect server.py:mcp

# Run from project config
fastmcp run

# Override transport at runtime
fastmcp run --transport stdio
```
