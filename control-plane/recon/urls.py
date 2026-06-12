from django.contrib import admin
from django.urls import path
from core.views import findings_board

urlpatterns = [
    path("", findings_board, name="findings"),
    path("admin/", admin.site.urls),
]
