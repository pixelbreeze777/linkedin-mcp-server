from starlette.requests import Request
from urllib.parse import parse_qs, urlparse

from linkedin_mcp_server.oauth_auth import MinimalOAuthProvider


def _request(
    *,
    method: str,
    path: str,
    headers: list[tuple[bytes, bytes]] | None = None,
    body: bytes = b"",
) -> Request:
    async def _receive() -> dict[str, object]:
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(
        {
            "type": "http",
            "method": method,
            "path": path,
            "headers": headers or [],
        },
        receive=_receive,
    )


async def test_token_endpoint_issues_token():
    provider = MinimalOAuthProvider(
        base_url="https://example.com",
        client_id="cid",
        client_secret="secret",
        allowed_redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
    )
    req = _request(
        method="POST",
        path="/token",
        headers=[(b"content-type", b"application/x-www-form-urlencoded")],
        body=b"grant_type=client_credentials&client_id=cid&client_secret=secret",
    )
    resp = await provider._token_endpoint(req)
    assert resp.status_code == 200


async def test_verify_token_rejects_invalid_token():
    provider = MinimalOAuthProvider(
        base_url="https://example.com",
        client_id="cid",
        client_secret="secret",
        allowed_redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
    )
    token = await provider.verify_token("invalid")
    assert token is None


async def test_authorization_code_pkce_flow():
    provider = MinimalOAuthProvider(
        base_url="https://example.com",
        client_id="cid",
        client_secret="secret",
        allowed_redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
    )
    authorize_req = _request(
        method="GET",
        path="/authorize",
        headers=[],
    )
    authorize_req.scope["query_string"] = (
        b"response_type=code&client_id=cid"
        b"&redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback"
        b"&state=s123&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        b"&code_challenge_method=S256"
    )
    authorize_resp = await provider._authorize_endpoint(authorize_req)
    assert authorize_resp.status_code == 302
    location = authorize_resp.headers["location"]
    params = parse_qs(urlparse(location).query)
    code = params["code"][0]

    token_req = _request(
        method="POST",
        path="/token",
        headers=[(b"content-type", b"application/x-www-form-urlencoded")],
        body=(
            "grant_type=authorization_code&client_id=cid&client_secret=secret"
            f"&code={code}"
            "&redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fmcp%2Fauth_callback"
            "&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        ).encode(),
    )
    token_resp = await provider._token_endpoint(token_req)
    assert token_resp.status_code == 200
