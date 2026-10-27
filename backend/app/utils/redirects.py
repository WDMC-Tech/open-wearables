from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def _origin(scheme: str, netloc: str) -> str:
    return f"{scheme}://{netloc}".lower().rstrip("/")


def is_allowed_redirect_uri(uri: str, allowed_origins: list[str]) -> bool:
    """True when ``uri`` is an absolute http(s) URL on one of ``allowed_origins``.

    Compares the exact scheme + host + port, so ``https://app.example.com.evil.com`` or
    ``https://evil.com/?https://app.example.com`` never match. Rejects credentials in the URL
    and backslashes (some browsers treat ``\\`` as ``/``, turning ``https:\\\\evil.com`` into
    another host).
    """
    if not uri or "\\" in uri or any(ch.isspace() for ch in uri):
        return False
    try:
        parts = urlsplit(uri)
        _ = parts.port  # raises on a malformed port
    except ValueError:
        return False
    if parts.scheme not in ("https", "http") or not parts.hostname or parts.username or parts.password:
        return False
    allowed = {o.strip().lower().rstrip("/") for o in allowed_origins if o.strip()}
    return _origin(parts.scheme, parts.netloc) in allowed


def with_query_params(uri: str, params: dict[str, str]) -> str:
    """``uri`` with ``params`` added to its query string (existing params are kept)."""
    parts = urlsplit(uri)
    query = parse_qsl(parts.query, keep_blank_values=True) + list(params.items())
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))
