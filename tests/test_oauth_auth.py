from starlette.requests import Request

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
    )
    token = await provider.verify_token("invalid")
    assert token is None
