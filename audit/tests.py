from unittest.mock import MagicMock, patch

import requests
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APITestCase

from .models import AuditReport
from .utils import (
    FetchTimeoutError,
    InvalidURLError,
    NonHTMLResponseError,
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


def _mock_response(content=b'', status_code=200, content_type='text/html'):
    """Builds a MagicMock that looks enough like a requests.Response for
    audit_url() to work with, including the streaming .iter_content path."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.headers = {'Content-Type': content_type}
    mock_resp.iter_content.return_value = [content] if content else []
    return mock_resp


class AuditUrlParsingTests(TestCase):
    """Unit tests for the parsing logic in audit/utils.py, per Task B (a):
    happy path plus at least two failure cases."""

    @patch('audit.utils.requests.get')
    def test_happy_path_extracts_expected_fields(self, mock_get):
        mock_get.return_value = _mock_response(SAMPLE_HTML)

        result = audit_url('https://example.com')

        self.assertEqual(result['http_status'], 200)
        self.assertEqual(result['title'], 'Sample Page')
        self.assertEqual(result['meta_description'], 'A short description of the page.')
        self.assertEqual(result['h1_count'], 2)
        self.assertEqual(result['images_total'], 3)
        # b.png has no alt attribute at all, c.png has alt="" - both count
        # as "missing", a.png does not.
        self.assertEqual(result['images_missing_alt'], 2)
        self.assertGreater(result['word_count'], 0)
        # The script tag's content must not leak into the word count.
        self.assertNotIn('shouldNotBeCounted', ' '.join(str(result['word_count'])))

    def test_invalid_url_missing_scheme_raises_before_any_request(self):
        with self.assertRaises(InvalidURLError):
            audit_url('example.com/no-scheme')

    def test_invalid_url_empty_string_raises(self):
        with self.assertRaises(InvalidURLError):
            audit_url('')

    @patch('audit.utils.requests.get')
    def test_timeout_raises_fetch_timeout_error(self, mock_get):
        mock_get.side_effect = requests.exceptions.Timeout('simulated timeout')

        with self.assertRaises(FetchTimeoutError):
            audit_url('https://slow.example.com')

    @patch('audit.utils.requests.get')
    def test_non_html_response_raises(self, mock_get):
        mock_get.return_value = _mock_response(
            b'{"not": "html"}', content_type='application/json'
        )

        with self.assertRaises(NonHTMLResponseError):
            audit_url('https://api.example.com/data.json')


class AuditAPITests(APITestCase):
    """Thin API-layer tests: correct status codes and that every attempt
    (success or failure) is persisted to AuditReport."""

    @patch('audit.views.audit_url')
    def test_post_valid_url_returns_200_and_persists_report(self, mock_audit):
        mock_audit.return_value = {
            'url': 'https://example.com',
            'http_status': 200,
            'response_time_ms': 12.3,
            'title': 'Example',
            'meta_description': None,
            'h1_count': 1,
            'images_total': 0,
            'images_missing_alt': 0,
            'word_count': 42,
        }

        response = self.client.post(
            reverse('audit'), {'url': 'https://example.com'}, format='json'
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['title'], 'Example')
        self.assertEqual(AuditReport.objects.count(), 1)
        self.assertTrue(AuditReport.objects.first().succeeded)

    def test_post_missing_url_returns_400(self):
        response = self.client.post(reverse('audit'), {}, format='json')
        self.assertEqual(response.status_code, 400)

    @patch('audit.views.audit_url')
    def test_post_timeout_returns_504_and_persists_failure(self, mock_audit):
        mock_audit.side_effect = FetchTimeoutError('timed out')

        response = self.client.post(
            reverse('audit'), {'url': 'https://slow.example.com'}, format='json'
        )

        self.assertEqual(response.status_code, 504)
        self.assertEqual(response.data['error'], 'timeout')
        report = AuditReport.objects.first()
        self.assertFalse(report.succeeded)
        self.assertEqual(report.error_code, 'timeout')