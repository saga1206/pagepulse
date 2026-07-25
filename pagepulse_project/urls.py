from django.contrib import admin
from django.urls import include, path

from audit.views import index_view

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('audit.urls')),
    path('', index_view, name='index'),
]