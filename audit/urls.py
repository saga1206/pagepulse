from django.urls import path

from .views import AuditAPIView, AuditHistoryView

urlpatterns = [
    path('audit/', AuditAPIView.as_view(), name='audit'),
    path('audits/', AuditHistoryView.as_view(), name='audit-history'),
]