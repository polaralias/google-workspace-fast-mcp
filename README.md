# google-workspace-fast-mcp

FastMCP Python server for Google Workspace, implemented as a parity proxy over `google-workspace-mcp`.

## What is migrated

- Full Google Workspace MCP tool surface from `google-workspace-mcp`
- Existing Google connector/config env model via legacy runtime passthrough
- OAuth consent/UI routes are not exposed by this FastMCP server
- HTTP transport is API-key based

## Configuration

This server forwards through `scripts/google_workspace_stdio_bridge.mjs`, which boots
the Google Workspace MCP runtime from `../google-workspace-mcp` in stdio mode.

- `GOOGLE_WORKSPACE_LEGACY_REPO` (optional): absolute path to `google-workspace-mcp`
- `GOOGLE_WORKSPACE_NODE_BIN` / `NODE_BIN` (optional): Node executable
- All existing `google-workspace-mcp` env vars are passed through to the proxied runtime

API key auth for HTTP transport (required):

- `GOOGLE_WORKSPACE_MCP_API_KEY` (preferred), or
- `MCP_API_KEY`, or
- `MCP_API_KEYS` (comma-separated)

## Run

```bash
# HTTP (requires API key env)
python server.py

# stdio (no HTTP auth layer)
FASTMCP_TRANSPORT=stdio python server.py
```
