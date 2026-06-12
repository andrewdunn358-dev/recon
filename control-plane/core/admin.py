"""
Admin is the Phase 0 UI — fast, free, and enough to run the pilot. A themed
per-tenant dashboard is a Phase 1 concern (lift the wifi-portal pattern then).
"""
from django.contrib import admin
from .models import Tenant, Asset, Product, CVE, WatchSubscription, Finding


@admin.register(Tenant)
class TenantAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "scanning_authorised", "created_at")
    list_filter = ("scanning_authorised",)


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ("name", "tenant", "kind", "internet_facing", "target")
    list_filter = ("kind", "internet_facing", "tenant")
    search_fields = ("name", "target")


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    list_display = ("name", "vendor", "version", "asset", "source", "has_cpe")
    list_filter = ("vendor", "source")
    search_fields = ("name", "vendor", "cpe")

    @admin.display(boolean=True, description="CPE")
    def has_cpe(self, obj):
        return bool(obj.cpe)


@admin.register(CVE)
class CVEAdmin(admin.ModelAdmin):
    list_display = ("cve_id", "in_kev", "epss", "cvss", "cwe", "published")
    list_filter = ("in_kev",)
    search_fields = ("cve_id", "title", "summary")


@admin.register(WatchSubscription)
class WatchAdmin(admin.ModelAdmin):
    list_display = ("tenant", "vendor", "product")
    list_filter = ("tenant",)


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ("cve_id", "asset", "priority", "status", "match_confidence", "notified")
    list_filter = ("priority", "status", "match_confidence", "tenant")
    search_fields = ("cve__cve_id", "asset__name")
    list_editable = ("status",)
