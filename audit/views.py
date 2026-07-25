"""Views for the Page Pulse audit tool. Kept intentionally thin — all
fetching/parsing logic lives in utils.py, all persistence logic lives
in the AuditReport manager."""
import logging

from django.shortcuts import render
from django.views.decorators.csrf import ensure_csrf_cookie
from rest_framework import status
from rest_framework.generics import ListAPIView
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import AuditReport
from .serializers import AuditReportSerializer, AuditRequestSerializer
from .utils import AuditError, audit_url

logger = logging.getLogger(__name__)


@ensure_csrf_cookie
def index_view(request):
    """Serves the single-page frontend that calls /api/audit/.
    ensure_csrf_cookie guarantees the csrftoken cookie is set on first
    load so the page's own JS can attach it to its POST request."""
    return render(request, "audit/index.html")


class AuditAPIView(APIView):
    """POST /api/audit/  { "url": "https://example.com" }

    Runs the audit synchronously and returns the report. Persists every
    attempt (success or failure) via AuditReport.objects.
    """

    def post(self, request: Request) -> Response:
        request_serializer = AuditRequestSerializer(data=request.data)
        request_serializer.is_valid(raise_exception=True)
        url = request_serializer.validated_data["url"]

        try:
            result = audit_url(url)
        except AuditError as exc:
            report = AuditReport.objects.log_failure(
                url=url, error_code=exc.code, error_message=str(exc)
            )
            return Response(
                {"error": exc.code, "detail": str(exc), "report_id": report.id},
                status=exc.status_code,
            )
        except Exception:
            # Anything that isn't an AuditError is a bug, not an
            # expected failure mode. Log it for us, but never leak a
            # stack trace or exception message to the client.
            logger.exception("Unexpected error auditing url=%r", url)
            AuditReport.objects.log_failure(
                url=url, error_code="internal_error", error_message="Unexpected server error."
            )
            return Response(
                {"error": "internal_error", "detail": "Something went wrong on our end."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        report = AuditReport.objects.log_success(url=result["url"], result=result)
        return Response(AuditReportSerializer(report).data, status=status.HTTP_200_OK)


class AuditHistoryView(ListAPIView):
    """GET /api/audits/  - most recent audits, newest first."""
    queryset = AuditReport.objects.all()[:50]
    serializer_class = AuditReportSerializer