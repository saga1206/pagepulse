"""Models for the Page Pulse audit tool."""
from __future__ import annotations

from typing import Optional

from django.db import models


class AuditReportManager(models.Manager):
    """Encapsulates *how* an audit attempt gets persisted, so views.py
    doesn't need to know the model's field names or unpack a raw dict
    itself — it just hands over a result or an error."""

    def log_success(self, url: str, result: dict) -> "AuditReport":
        """Persists a successful audit. `result` is the dict returned
        by audit.utils.audit_url() (its own `url` key is dropped in
        favor of the possibly-redirect-resolved `url` argument)."""
        return self.create(
            url=url,
            succeeded=True,
            http_status=result["http_status"],
            response_time_ms=result["response_time_ms"],
            title=result["title"],
            meta_description=result["meta_description"],
            h1_count=result["h1_count"],
            images_total=result["images_total"],
            images_missing_alt=result["images_missing_alt"],
            word_count=result["word_count"],
        )

    def log_failure(self, url: str, error_code: str, error_message: str) -> "AuditReport":
        """Persists a failed audit attempt."""
        return self.create(
            url=url,
            succeeded=False,
            error_code=error_code,
            error_message=error_message,
        )


class AuditReport(models.Model):
    """One row per audited URL. Keeping a history in Postgres (rather
    than only returning the JSON and forgetting it) makes it possible
    to debug a "why did this fail" report after the fact."""

    url = models.URLField(max_length=2048)
    requested_at = models.DateTimeField(auto_now_add=True, db_index=True)

    succeeded = models.BooleanField(default=False)

    # Populated on success.
    http_status = models.PositiveIntegerField(null=True, blank=True)
    response_time_ms = models.FloatField(null=True, blank=True)
    title = models.CharField(max_length=1024, null=True, blank=True)
    meta_description = models.TextField(null=True, blank=True)
    h1_count = models.PositiveIntegerField(null=True, blank=True)
    images_total = models.PositiveIntegerField(null=True, blank=True)
    images_missing_alt = models.PositiveIntegerField(null=True, blank=True)
    word_count = models.PositiveIntegerField(null=True, blank=True)

    # Populated on failure.
    error_code = models.CharField(max_length=64, null=True, blank=True)
    error_message = models.TextField(null=True, blank=True)

    objects = AuditReportManager()

    class Meta:
        ordering = ["-requested_at"]

    def __str__(self) -> str:
        status = "ok" if self.succeeded else f"failed ({self.error_code})"
        return f"{self.url} [{status}]"