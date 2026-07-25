"""
Core "Page Pulse" auditing logic.

Kept separate from views.py so it can be unit tested without touching
Django's request/response cycle, and so the parsing/security rules live
in one place.
"""
from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from django.conf import settings

# Redirect status codes we're willing to follow manually.
_REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})

_USER_AGENT = "PagePulse-Audit-Bot/1.0"


class AuditError(Exception):
    """Base class for all *expected* audit failures. Views should catch
    this (or a subclass) and turn it into a clean JSON response instead
    of letting a raw exception/stack trace reach the client."""
    code = "audit_error"
    status_code = 400


class InvalidURLError(AuditError):
    """Raised when the submitted URL is malformed or uses a disallowed
    scheme/host, before any network call is made."""
    code = "invalid_url"
    status_code = 400


class BlockedAddressError(AuditError):
    """Raised when the URL (or a redirect target) resolves to a private,
    loopback, link-local, or otherwise internal IP address. This is the
    core SSRF guard — without it, this endpoint would let anyone probe
    the server's own network (e.g. the AWS metadata service) via a
    seemingly ordinary "audit this URL" request."""
    code = "blocked_address"
    status_code = 400


class TooManyRedirectsError(AuditError):
    """Raised when a URL redirects more times than we're willing to
    follow."""
    code = "too_many_redirects"
    status_code = 400


class FetchTimeoutError(AuditError):
    """Raised on a connect/read timeout, or when the overall wall-clock
    budget for fetching the page is exceeded."""
    code = "timeout"
    status_code = 504


class NonHTMLResponseError(AuditError):
    """Raised when the final response's Content-Type isn't HTML."""
    code = "non_html_response"
    status_code = 422


class UnreachableError(AuditError):
    """Raised on DNS failure, connection refused, or the connection
    dropping mid-read."""
    code = "unreachable"
    status_code = 502


@dataclass(frozen=True)
class _ValidatedURL:
    """A URL that has passed scheme/host validation. Kept as its own
    type so callers can't accidentally pass an unvalidated string to
    the parts of the code that assume validation already happened."""
    url: str
    
_NAT64_WELL_KNOWN_PREFIX = ipaddress.ip_network("64:ff9b::/96")


def _embedded_ipv4(ip_obj: ipaddress.IPv6Address):
    """Extract the real IPv4 address from an IPv6 address that's just an
    IPv4 address in disguise..."""
    if ip_obj.ipv4_mapped is not None:
        return ip_obj.ipv4_mapped
    if ip_obj in _NAT64_WELL_KNOWN_PREFIX:
        return ipaddress.IPv4Address(int(ip_obj) & 0xFFFFFFFF)
    return None


def _is_safe_ip(ip_str: str) -> bool:
    """True if the address is a normal public, routable address."""
    ip_obj = ipaddress.ip_address(ip_str)

    if isinstance(ip_obj, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(ip_obj)
        if embedded is not None:
            ip_obj = embedded

    return not (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )

def _validate_url(url: str) -> _ValidatedURL:
    """Structural validation only (scheme/host present). Does not touch
    the network — call `_assert_resolves_to_public_address` separately
    once you're ready to actually connect."""
    if not url or not isinstance(url, str):
        raise InvalidURLError("URL is required.")

    url = url.strip()
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise InvalidURLError("URL must start with http:// or https://.")
    if not parsed.hostname:
        raise InvalidURLError("URL is missing a host.")

    return _ValidatedURL(url)


def _assert_resolves_to_public_address(url: str) -> None:
    """Resolves the URL's hostname and rejects it if any resolved
    address is private/internal. Must be called for the original URL
    *and* for every redirect hop — a malicious or compromised server
    can otherwise redirect a "safe" public URL straight to an internal
    IP and bypass a check done only once up front.
    """
    hostname = urlparse(url).hostname
    port = urlparse(url).port or (443 if url.startswith("https") else 80)

    try:
        addr_infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnreachableError(f"Could not resolve host: {hostname}.") from exc

    for family, _, _, _, sockaddr in addr_infos:
        ip_str = sockaddr[0]
        if not _is_safe_ip(ip_str):
            raise BlockedAddressError(
                "This URL resolves to a private or internal address, "
                "which cannot be audited."
            )


def _extract_visible_text(soup: BeautifulSoup) -> str:
    """Strip script/style/noscript content and return remaining visible
    text, used for the approximate word count."""
    for tag in soup(["script", "style", "noscript", "template"]):
        tag.decompose()
    return soup.get_text(separator=" ")


def _read_capped_body(response: requests.Response, max_bytes: int, deadline: float) -> bytes:
    """Reads the response body up to `max_bytes`, aborting early (and
    respecting `deadline`, an absolute time.monotonic() cutoff) rather
    than trusting the server's own pace — a slow-trickling response
    could otherwise stay "alive" past the intended timeout budget one
    read-timeout-sized chunk at a time.
    """
    chunks: list[bytes] = []
    total = 0
    try:
        for chunk in response.iter_content(chunk_size=8192):
            if time.monotonic() > deadline:
                raise FetchTimeoutError("Timed out while reading the response body.")
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                break
    except requests.exceptions.RequestException as exc:
        raise UnreachableError(f"Connection dropped while reading the response: {exc}") from exc

    return b"".join(chunks)


def audit_url(url: str) -> dict:
    """Fetch `url` and return a dict report. Raises an AuditError
    subclass on any expected failure; never raises a raw
    requests/socket/bs4 exception."""
    validated = _validate_url(url)
    current_url = validated.url

    timeout_seconds = settings.PAGEPULSE_FETCH_TIMEOUT_SECONDS
    max_bytes = settings.PAGEPULSE_MAX_CONTENT_BYTES
    max_redirects = settings.PAGEPULSE_MAX_REDIRECTS
    connect_timeout = min(5.0, timeout_seconds)

    overall_deadline = time.monotonic() + timeout_seconds
    started = time.perf_counter()

    session = requests.Session()
    response: Optional[requests.Response] = None

    try:
        for hop in range(max_redirects + 1):
            _assert_resolves_to_public_address(current_url)

            try:
                response = session.get(
                    current_url,
                    timeout=(connect_timeout, timeout_seconds),
                    headers={"User-Agent": _USER_AGENT},
                    stream=True,
                    allow_redirects=False,
                )
            except requests.exceptions.Timeout as exc:
                raise FetchTimeoutError(
                    f"Timed out after {timeout_seconds}s fetching {current_url}."
                ) from exc
            except requests.exceptions.RequestException as exc:
                raise UnreachableError(f"Could not reach {current_url}: {exc}") from exc

            if response.status_code in _REDIRECT_STATUS_CODES:
                location = response.headers.get("Location")
                response.close()
                if not location:
                    raise UnreachableError("Server sent a redirect with no Location header.")
                current_url = _validate_url(urljoin(current_url, location)).url
                continue

            break
        else:
            raise TooManyRedirectsError(f"Exceeded {max_redirects} redirects.")

        content = _read_capped_body(response, max_bytes, overall_deadline)
        response_time_ms = round((time.perf_counter() - started) * 1000, 1)

        content_type = response.headers.get("Content-Type", "")
        if "html" not in content_type.lower():
            raise NonHTMLResponseError(
                f'Expected an HTML page, got Content-Type "{content_type or "unknown"}".'
            )

        soup = BeautifulSoup(content, "html.parser")

        title_tag = soup.title
        title = title_tag.string.strip() if title_tag and title_tag.string else None

        meta_description = None
        meta_tag = soup.find("meta", attrs={"name": "description"})
        if meta_tag and meta_tag.get("content"):
            meta_description = meta_tag["content"].strip()

        h1_count = len(soup.find_all("h1"))

        images = soup.find_all("img")
        images_missing_alt = sum(
            1 for img in images if not img.get("alt") or not img.get("alt").strip()
        )

        word_count = len(_extract_visible_text(soup).split())

        return {
            "url": current_url,
            "http_status": response.status_code,
            "response_time_ms": response_time_ms,
            "title": title,
            "meta_description": meta_description,
            "h1_count": h1_count,
            "images_total": len(images),
            "images_missing_alt": images_missing_alt,
            "word_count": word_count,
        }
    finally:
        if response is not None:
            response.close()
        session.close()