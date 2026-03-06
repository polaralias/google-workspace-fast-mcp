from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Iterable

from fastmcp.client.transports import StdioTransport
from fastmcp.server import create_proxy
from fastmcp.server.auth import AccessToken, TokenVerifier


class StaticApiKeyVerifier(TokenVerifier):
    def __init__(self, api_keys: Iterable[str], base_url: str | None = None) -> None:
        super().__init__(base_url=base_url)
        self._api_keys = [key for key in api_keys if key]

    async def verify_token(self, token: str) -> AccessToken | None:
        for key in self._api_keys:
            if secrets.compare_digest(token, key):
                return AccessToken(token=token, client_id="google-workspace-fast-mcp", scopes=[])
        return None


def _repo_root() -> Path:
    return Path(__file__).resolve().parent


def _legacy_root() -> Path:
    override = os.getenv("GOOGLE_WORKSPACE_LEGACY_REPO")
    if override:
        return Path(override).expanduser().resolve()
    return (_repo_root().parent / "google-workspace-mcp").resolve()


def _load_api_keys() -> list[str]:
    keys: list[str] = []

    preferred = os.getenv("GOOGLE_WORKSPACE_MCP_API_KEY")
    if preferred:
        keys.append(preferred.strip())

    single = os.getenv("MCP_API_KEY")
    if single:
        keys.append(single.strip())

    multi = os.getenv("MCP_API_KEYS")
    if multi:
        for raw in multi.split(","):
            token = raw.strip()
            if token:
                keys.append(token)

    return list(dict.fromkeys(keys))


def _http_transport_enabled() -> bool:
    transport_name = os.getenv("FASTMCP_TRANSPORT", "streamable-http").strip().lower()
    return transport_name != "stdio"


def build_server():
    legacy_root = _legacy_root()
    mcp_module = legacy_root / "dist" / "mcp.js"
    bridge_script = _repo_root() / "scripts" / "google_workspace_stdio_bridge.mjs"
    if not mcp_module.exists() or not bridge_script.exists():
        raise FileNotFoundError(
            "Missing Google Workspace bridge prerequisites. Ensure google-workspace-mcp exists and "
            "scripts/google_workspace_stdio_bridge.mjs is present."
        )

    api_keys = _load_api_keys()
    if _http_transport_enabled() and not api_keys:
        raise RuntimeError(
            "API key mode is required for HTTP transport. Set GOOGLE_WORKSPACE_MCP_API_KEY, "
            "MCP_API_KEY, or MCP_API_KEYS."
        )

    env = {key: str(value) for key, value in os.environ.items()}
    env["GOOGLE_WORKSPACE_LEGACY_REPO"] = str(legacy_root)
    env.setdefault("DOTENV_CONFIG_QUIET", "true")
    node_bin = os.getenv("GOOGLE_WORKSPACE_NODE_BIN", os.getenv("NODE_BIN", "node"))
    transport = StdioTransport(
        command=node_bin,
        args=[str(bridge_script)],
        env=env,
        cwd=str(_repo_root()),
    )

    auth = StaticApiKeyVerifier(api_keys=api_keys, base_url=os.getenv("BASE_URL")) if api_keys else None

    return create_proxy(
        transport,
        name="google-workspace-fast-mcp",
        instructions=(
            "FastMCP proxy for google-workspace-mcp in API-key deployment mode. "
            "All workspace tools are proxied from the legacy runtime over stdio, without exposing OAuth consent UI."
        ),
        auth=auth,
    )


server = build_server()


def main() -> None:
    transport_name = os.getenv("FASTMCP_TRANSPORT", "streamable-http").strip().lower()

    if transport_name == "stdio":
        server.run()
    else:
        host = os.getenv("HOST", "0.0.0.0")
        port = int(os.getenv("PORT", "8000"))
        server.run(transport=transport_name, host=host, port=port)


if __name__ == "__main__":
    main()
