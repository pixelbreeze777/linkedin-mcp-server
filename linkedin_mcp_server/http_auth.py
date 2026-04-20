"""HTTP authentication helpers for streamable MCP transport."""

from __future__ import annotations

import hmac

from fastmcp.server.auth import AccessToken, TokenVerifier


class BearerTokenVerifier(TokenVerifier):
    """Validate a single shared bearer token from configuration."""

    def __init__(self, *, expected_token: str) -> None:
        super().__init__()
        self._expected_token = expected_token

    async def verify_token(self, token: str) -> AccessToken | None:
        """Accept requests that present the configured shared token."""
        if not hmac.compare_digest(token, self._expected_token):
            return None

        return AccessToken(
            token=token,
            client_id="linkedin-mcp-shared-token",
            scopes=[],
            expires_at=None,
            claims={"sub": "linkedin-mcp-shared-token"},
        )
