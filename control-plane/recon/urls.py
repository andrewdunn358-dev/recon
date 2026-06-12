from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import path
from core.views import dashboard, scan_start, scan_status

urlpatterns = [
    path("", dashboard, name="dashboard"),
    path("scan/start/", scan_start, name="scan_start"),
    path("scan/status/", scan_status, name="scan_status"),
    path("login/", auth_views.LoginView.as_view(
        template_name="registration/login.html"), name="login"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("admin/", admin.site.urls),
]
