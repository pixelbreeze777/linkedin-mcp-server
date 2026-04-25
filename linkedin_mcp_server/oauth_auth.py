"""Minimal OAuth provider for MCP HTTP auth."""

from __future__ import annotations

import base64
import secrets
import time
from dataclasses import dataclass
from typing import Any

from fastmcp.server.auth import AccessToken, AuthProvider
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route


@dataclass
class _TokenState:
    client_id: str
    expires_at: int
    scopes: list[str]


class MinimalOAuthProvider(AuthProvider):
    """OAuth client-credentials provider with in-memory access tokens."""

    def __init__(
        self,
        *,
        base_url: str,
        client_id: str,
        client_secret: str,
        token_ttl_seconds: int = 3600,
        required_scopes: list[str] | None = None,
    ) -> None:
        super().__init__(base_url=base_url, required_scopes=required_scopes)
        self._client_id = client_id
        self._client_secret = client_secret
        self._token_ttl_seconds = token_ttl_seconds
        self._token_store: dict[str, _TokenState] = {}

    async def verify_token(self, token: str) -> AccessToken | None:
        state = self._token_store.get(token)
        if state is None:
            return None
        if state.expires_at <= int(time.time()):
            self._token_store.pop(token, None)
            return None
        return AccessToken(
            token=token,
            client_id=state.client_id,
            scopes=state.scopes,
            expires_at=state.expires_at,
            claims={"sub": state.client_id},
        )

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        self.set_mcp_path(mcp_path)
        return [
            Route(
                "/token",
                endpoint=self._token_endpoint,
                methods=["POST", "OPTIONS"],
            ),
            Route(
                "/.well-known/oauth-authorization-server",
                endpoint=self._oauth_metadata,
                methods=["GET"],
            ),
        ]

    async def _token_endpoint(self, request: Request) -> JSONResponse:
        client_id, client_secret = await self._extract_client_credentials(request)
        if client_id != self._client_id or client_secret != self._client_secret:
            return JSONResponse(
                {"error": "invalid_client"},
                status_code=401,
            )

        form = await request.form()
        grant_type = str(form.get("grant_type") or "")
        if grant_type != "client_credentials":
            return JSONResponse(
                {"error": "unsupported_grant_type"},
                status_code=400,
            )

        scope_raw = str(form.get("scope") or "").strip()
        scopes = [s for s in scope_raw.split() if s] if scope_raw else []
        now = int(time.time())
        expires_at = now + self._token_ttl_seconds
        token = secrets.token_urlsafe(48)
        self._token_store[token] = _TokenState(
            client_id=client_id,
            expires_at=expires_at,
            scopes=scopes,
        )
        return JSONResponse(
            {
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": self._token_ttl_seconds,
                "scope": " ".join(scopes),
            },
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
            },
        )

    async def _oauth_metadata(self, request: Request) -> JSONResponse:
        del request
        base = str(self.base_url).rstrip("/")  # type: ignore[union-attr]
        metadata: dict[str, Any] = {
            "issuer": f"{base}/",
            "token_endpoint": f"{base}/token",
            "grant_types_supported": ["client_credentials"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
        }
        if self.required_scopes:
            metadata["scopes_supported"] = self.required_scopes
        return JSONResponse(metadata)

    async def _extract_client_credentials(self, request: Request) -> tuple[str, str]:
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("basic "):
            encoded = auth_header.split(" ", 1)[1].strip()
            try:
                decoded = base64.b64decode(encoded).decode("utf-8")
                client_id, client_secret = decoded.split(":", 1)
                return client_id, client_secret
            except Exception:
                return "", ""

        form = await request.form()
        return (
            str(form.get("client_id") or ""),
            str(form.get("client_secret") or ""),
        )
