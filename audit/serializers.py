"""Serializers for the Page Pulse audit API."""
from rest_framework import serializers

from .models import AuditReport


class AuditRequestSerializer(serializers.Serializer):
    """Validates the incoming {"url": "..."} body. Deliberately a plain
    CharField (not URLField) so audit.utils raises its own typed
    InvalidURLError with a consistent error shape instead of DRF's
    default field-error format — see views.py."""
    url = serializers.CharField(max_length=2048, allow_blank=False)


class AuditReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = AuditReport
        fields = [
            "id", "url", "requested_at", "succeeded",
            "http_status", "response_time_ms", "title", "meta_description",
            "h1_count", "images_total", "images_missing_alt", "word_count",
            "error_code", "error_message",
        ]
        read_only_fields = fields