import socket
from unittest.mock import MagicMock, patch

import requests
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APITestCase

from .models import AuditReport
from .utils import (
    BlockedAddressError,
    FetchTimeoutError,
    InvalidURLError,
    NonHTMLResponseError,
    TooManyRedirectsError,
    UnreachableError,
    _is_safe_ip,
    audit_url,
)

SAMPLE_HTML = b"""
<html>
<head>
    <title>Sample Page</title>
    <meta name="description" content="A short description of the page.">
</head>
<body>
    <h1>Welcome</h1>
    <h1>Second heading, on purpose</h1>
    <img src="a.png" alt="A described image">
    <img src="b.png">
    <img src="c.png" alt="">
    <p>Some visible words go here for the word count to pick up.</p>
    <script>var shouldNotBeCounted = "as words";</script>
</body>
</html>
"""

PUBLIC_IP = "93.184.216.34"  # a stand-in public IPv4, not asserted against externally


def _mock_response(content=b"", status_code=200, content_type="text/html", headers=None):
    """Builds a MagicMock that looks enough like a requests.Response for
    audit_url() to work with, including the streaming .iter_content path."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.headers = headers or {"Content-Type": content_type}
    mock_resp.iter_content.return_value = [content] if content else []
    return mock_resp


def _addrinfo_for(ip: str, port: int = 443):
    """Builds a fake socket.getaddrinfo() return value for a single IPv4
    address, shaped the way _assert_resolves_to_public_address expects."""
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]


class IsSafeIpTests(TestCase):
    """Direct unit tests for the SSRF address-safety check, including the
    IPv4-mapped / NAT64 unwrap logic added after a real false-positive
    (public hosts being misclassified as private due to how DNS wrapped
    their address, not what the address actually was)."""

    def test_public_ipv4_is_safe(self):
        self.assertTrue(_is_safe_ip("8.8.8.8"))

    def test_private_ipv4_is_unsafe(self):
        self.assertFalse(_is_safe_ip("10.0.0.5"))

    def test_loopback_is_unsafe(self):
        self.assertFalse(_is_safe_ip("127.0.0.1"))

    def test_aws_metadata_link_local_is_unsafe(self):
        self.assertFalse(_is_safe_ip("169.254.169.254"))

    def test_ipv4_mapped_public_address_is_safe(self):
        # ::ffff:8.8.8.8 wraps a public IPv4 address. Must unwrap to the
        # real address rather than being blocked just because of the
        # IPv4-mapped IPv6 encoding.
        self.assertTrue(_is_safe_ip("::ffff:8.8.8.8"))

    def test_ipv4_mapped_private_address_is_unsafe(self):
        self.assertFalse(_is_safe_ip("::ffff:10.0.0.5"))

    def test_nat64_synthesized_public_address_is_safe(self):
        # 64:ff9b::808:808 embeds 8.8.8.8 under the RFC 6052 well-known
        # NAT64 prefix.
        self.assertTrue(_is_safe_ip("64:ff9b::808:808"))

    def test_nat64_synthesized_private_address_is_unsafe(self):
        # Embeds 169.254.169.254 (the AWS metadata address).
        self.assertFalse(_is_safe_ip("64:ff9b::a9fe:a9fe"))


class AuditUrlParsingTests(TestCase):
    """Unit tests for the parsing/fetch logic in audit/utils.py.

    DNS resolution (socket.getaddrinfo) and the outbound request
    (requests.Session.get) are both mocked, so these never touch the
    real network and aren't affected by DNS/connectivity in whatever
    environment the suite runs in.
    """

    @patch("audit.utils.requests.Session.get")
    @patch("audit.utils.socket.getaddrinfo")
    def test_happy_path_extracts_expected_fields(self, mock_getaddrinfo, mock_get):
        mock_getaddrinfo.return_value = _addrinfo_for(PUBLIC_IP)
        mock_get.return_value = _mock_response(SAMPLE_HTML)

        result = audit_url("https://example.com")

        self.assertEqual(result["http_status"], 200)
        self.assertEqual(result["title"], "Sample Page")
        self.assertEqual(result["meta_description"], "A short description of the page.")
        self.assertEqual(result["h1_count"], 2)
        self.assertEqual(result["images_total"], 3)
        # b.png has no alt attribute at all, c.png has alt="" - both count
        # as "missing", a.png does not.
        self.assertEqual(result["images_missing_alt"], 2)
        self.assertGreater(result["word_count"], 0)

    def test_invalid_url_missing_scheme_raises_before_any_request(self):
        with self.assertRaises(InvalidURLError):
            audit_url("example.com/no-scheme")

    def test_invalid_url_empty_string_raises(self):
        with self.assertRaises(InvalidURLError):
            audit_url("")

    @patch("audit.utils.requests.Session.get")
    @patch("audit.utils.socket.getaddrinfo")
    def test_timeout_raises_fetch_timeout_error(self, mock_getaddrinfo, mock_get):
        mock_getaddrinfo.return_value = _addrinfo_for(PUBLIC_IP)
        mock_get.side_effect = requests.exceptions.Timeout("simulated timeout")

        with self.assertRaises(FetchTimeoutError):
            audit_url("https://slow.example.com")

    @patch("audit.utils.requests.Session.get")
    @patch("audit.utils.socket.getaddrinfo")
    def test_non_html_response_raises(self, mock_getaddrinfo, mock_get):
        mock_getaddrinfo.return_value = _addrinfo_for(PUBLIC_IP)
        mock_get.return_value = _mock_response(
            b'{"not": "html"}', content_type="application/json"
        )

        with self.assertRaises(NonHTMLResponseError):
            audit_url("https://api.example.com/data.json")

    @patch("audit.utils.socket.getaddrinfo")
    def test_private_address_raises_blocked_address_before_any_request(self, mock_getaddrinfo):
        # Resolves to loopback - must be rejected from DNS resolution
        # alone, before any HTTP request is attempted.
        mock_getaddrinfo.return_value = _addrinfo_for("127.0.0.1")

        with self.assertRaises(BlockedAddressError):
            audit_url("https://internal.example.com")

    @patch("audit.utils.socket.getaddrinfo")
    def test_unresolvable_host_raises_unreachable(self, mock_getaddrinfo):
        mock_getaddrinfo.side_effect = socket.gaierror("simulated DNS failure")

        with self.assertRaises(UnreachableError):
            audit_url("https://does-not-resolve.example.invalid")

    @patch("audit.utils.requests.Session.get")
    @patch("audit.utils.socket.getaddrinfo")
    def test_redirect_is_followed_and_revalidated(self, mock_getaddrinfo, mock_get):
        mock_getaddrinfo.return_value = _addrinfo_for(PUBLIC_IP)
        redirect_response = _mock_response(
            b"", status_code=302, headers={"Location": "https://final.example.com/"}
        )
        final_response = _mock_response(SAMPLE_HTML)
        mock_get.side_effect = [redirect_response, final_response]

        result = audit_url("https://start.example.com")

        self.assertEqual(result["url"], "https://final.example.com/")
        # DNS/SSRF check must run again on the redirect target, not just
        # the original URL - this is the whole point of the guard.
        self.assertEqual(mock_getaddrinfo.call_count, 2)

    @patch("audit.utils.requests.Session.get")
    @patch("audit.utils.socket.getaddrinfo")
    def test_too_many_redirects_raises(self, mock_getaddrinfo, mock_get):
        mock_getaddrinfo.return_value = _addrinfo_for(PUBLIC_IP)
        mock_get.return_value = _mock_response(
            b"", status_code=302, headers={"Location": "https://start.example.com/"}
        )

        with self.assertRaises(TooManyRedirectsError):
            audit_url("https://start.example.com")


class AuditAPITests(APITestCase):
    """Thin API-layer tests: correct status codes and that every attempt
    (success or failure) is persisted to AuditReport. These mock
    audit.views.audit_url directly, so they're unaffected by changes to
    utils.py's internals."""

    @patch("audit.views.audit_url")
    def test_post_valid_url_returns_200_and_persists_report(self, mock_audit):
        mock_audit.return_value = {
            "url": "https://example.com",
            "http_status": 200,
            "response_time_ms": 12.3,
            "title": "Example",
            "meta_description": None,
            "h1_count": 1,
            "images_total": 0,
            "images_missing_alt": 0,
            "word_count": 42,
        }

        response = self.client.post(
            reverse("audit"), {"url": "https://example.com"}, format="json"
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["title"], "Example")
        self.assertEqual(AuditReport.objects.count(), 1)
        self.assertTrue(AuditReport.objects.first().succeeded)

    def test_post_missing_url_returns_400(self):
        response = self.client.post(reverse("audit"), {}, format="json")
        self.assertEqual(response.status_code, 400)

    @patch("audit.views.audit_url")
    def test_post_timeout_returns_504_and_persists_failure(self, mock_audit):
        mock_audit.side_effect = FetchTimeoutError("timed out")

        response = self.client.post(
            reverse("audit"), {"url": "https://slow.example.com"}, format="json"
        )

        self.assertEqual(response.status_code, 504)
        self.assertEqual(response.data["error"], "timeout")
        report = AuditReport.objects.first()
        self.assertFalse(report.succeeded)
        self.assertEqual(report.error_code, "timeout")

    @patch("audit.views.audit_url")
    def test_post_blocked_address_returns_400_and_persists_failure(self, mock_audit):
        mock_audit.side_effect = BlockedAddressError("blocked")

        response = self.client.post(
            reverse("audit"), {"url": "https://internal.example.com"}, format="json"
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["error"], "blocked_address")
        report = AuditReport.objects.first()
        self.assertFalse(report.succeeded)
        self.assertEqual(report.error_code, "blocked_address")