"""Admin registration for AuditReport. Read-only: this table is an
append-only log, not something an operator should hand-edit."""
from django.contrib import admin
from django.http import HttpRequest

from .models import AuditReport


@admin.register(AuditReport)
class AuditReportAdmin(admin.ModelAdmin):
    list_display = ("url", "succeeded", "http_status", "requested_at")
    list_filter = ("succeeded",)
    search_fields = ("url",)
    readonly_fields = [f.name for f in AuditReport._meta.fields]

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def has_change_permission(self, request: HttpRequest, obj=None) -> bool:
        return False