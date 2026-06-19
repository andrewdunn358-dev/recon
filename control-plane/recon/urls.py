from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework.authtoken.views import obtain_auth_token
from core.views import dashboard, findings as findings_view, attack_surface, scan_start, scan_status, clients, client_detail, client_scan_start, asset_scan_start, asset_audit, remediate_start, remediate_status, suppress_start, unsuppress, suppressions, remediations
from core.api import TenantViewSet, AssetViewSet, FindingViewSet, ScanViewSet

router = DefaultRouter()
router.register("tenants", TenantViewSet)
router.register("assets", AssetViewSet, basename="asset")
router.register("findings", FindingViewSet, basename="finding")
router.register("scans", ScanViewSet)

urlpatterns = [
    path("", dashboard, name="dashboard"),
    path("clients/", clients, name="clients"),
    path("findings/", findings_view, name="findings"),
    path("clients/<slug:slug>/", client_detail, name="client_detail"),
    path("clients/<slug:slug>/scan/", client_scan_start, name="client_scan_start"),
    path("clients/<slug:slug>/asset/<int:asset_id>/scan/", asset_scan_start, name="asset_scan_start"),
    path("clients/<slug:slug>/asset/<int:asset_id>/audit/", asset_audit, name="asset_audit"),
    path("scan/start/", scan_start, name="scan_start"),
    path("scan/status/", scan_status, name="scan_status"),
    path("remediate/<int:finding_id>/", remediate_start, name="remediate_start"),
    path("remediate/status/", remediate_status, name="remediate_status"),
    path("suppress/<int:finding_id>/", suppress_start, name="suppress_start"),
    path("suppress/<int:sup_id>/undo/", unsuppress, name="unsuppress"),
    path("suppressions/", suppressions, name="suppressions"),
    path("attack-surface/", attack_surface, name="attack_surface"),
    path("remediations/", remediations, name="remediations"),
    path("api/", include(router.urls)),
    path("api/auth-token/", obtain_auth_token, name="api_auth_token"),
    path("login/", auth_views.LoginView.as_view(
        template_name="registration/login.html"), name="login"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("admin/", admin.site.urls),
]
