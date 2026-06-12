"""
REST API (§ step 3) — the integration seam for SynthOps and any other caller.

Token-authenticated, machine-to-machine. Lets a client:
  - sync tenants/assets in     (POST /api/tenants, /api/assets)
  - trigger an assessment       (POST /api/scans)
  - poll a scan + read findings (GET  /api/scans/{id}, /api/findings)
  - read findings with fix links(GET  /api/findings?tenant=slug&priority=P1)

Mint a token:  manage.py api_token <username>
Call with:     Authorization: Token <token>
"""
from rest_framework import serializers, viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response

from .models import Tenant, Asset, Product, Finding, ScanJob
from .tasks import adhoc_assess


# ----- serializers ---------------------------------------------------------

class TenantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tenant
        fields = ["id", "slug", "name", "scanning_authorised", "created_at"]


class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = ["id", "vendor", "name", "version", "cpe", "source"]


class AssetSerializer(serializers.ModelSerializer):
    tenant = serializers.SlugRelatedField(slug_field="slug", queryset=Tenant.objects.all())
    products = ProductSerializer(many=True, read_only=True)

    class Meta:
        model = Asset
        fields = ["id", "tenant", "name", "kind", "internet_facing", "target",
                  "last_seen", "products"]


class FindingSerializer(serializers.ModelSerializer):
    tenant = serializers.SlugRelatedField(slug_field="slug", read_only=True)
    asset = serializers.CharField(source="asset.name", read_only=True)
    target = serializers.CharField(source="asset.target", read_only=True)
    label = serializers.ReadOnlyField()
    cve_id = serializers.ReadOnlyField()
    in_kev = serializers.SerializerMethodField()
    epss = serializers.SerializerMethodField()
    remediation_links = serializers.ReadOnlyField()

    class Meta:
        model = Finding
        fields = ["id", "tenant", "asset", "target", "priority", "status", "source",
                  "label", "cve_id", "in_kev", "epss", "severity", "match_confidence",
                  "match_reason", "remediation", "remediation_links",
                  "first_seen", "last_seen"]

    def get_in_kev(self, f):
        return bool(f.cve and f.cve.in_kev)

    def get_epss(self, f):
        return f.cve.epss if f.cve else None


class ScanJobSerializer(serializers.ModelSerializer):
    tenant = serializers.SlugRelatedField(slug_field="slug", read_only=True)

    class Meta:
        model = ScanJob
        fields = ["id", "target", "tenant", "status", "phase", "progress", "total",
                  "summary", "do_nuclei", "do_ports", "created_at", "started_at",
                  "finished_at"]


class ScanCreateSerializer(serializers.Serializer):
    target = serializers.CharField()
    nuclei = serializers.BooleanField(default=True)
    ports = serializers.BooleanField(default=False)
    authorised = serializers.BooleanField(default=False)
    tenant = serializers.SlugRelatedField(
        slug_field="slug", queryset=Tenant.objects.all(), required=False, allow_null=True)

    def validate_authorised(self, v):
        if not v:
            raise serializers.ValidationError(
                "You must confirm authorisation to scan this target (§11).")
        return v


# ----- viewsets ------------------------------------------------------------

class TenantViewSet(viewsets.ModelViewSet):
    queryset = Tenant.objects.all()
    serializer_class = TenantSerializer
    lookup_field = "slug"


class AssetViewSet(viewsets.ModelViewSet):
    serializer_class = AssetSerializer

    def get_queryset(self):
        qs = Asset.objects.select_related("tenant").prefetch_related("products")
        tenant = self.request.query_params.get("tenant")
        if tenant:
            qs = qs.filter(tenant__slug=tenant)
        if self.request.query_params.get("internet_facing") == "true":
            qs = qs.filter(internet_facing=True)
        return qs


class FindingViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = FindingSerializer

    def get_queryset(self):
        qs = Finding.objects.select_related("cve", "asset", "tenant", "product")
        p = self.request.query_params
        if p.get("tenant"):
            qs = qs.filter(tenant__slug=p["tenant"])
        if p.get("priority"):
            qs = qs.filter(priority=p["priority"])
        if p.get("source"):
            qs = qs.filter(source=p["source"])
        if p.get("kev") == "true":
            qs = qs.filter(cve__in_kev=True)
        return qs.order_by("priority")


class ScanViewSet(viewsets.ReadOnlyModelViewSet):
    """GET status/list, POST to trigger. Findings stream onto the job as it runs."""
    queryset = ScanJob.objects.all()
    serializer_class = ScanJobSerializer

    def create(self, request):
        s = ScanCreateSerializer(data=request.data)
        s.is_valid(raise_exception=True)
        d = s.validated_data
        job = ScanJob.objects.create(
            target=d["target"].strip(),
            do_nuclei=d["nuclei"], do_ports=d["ports"],
            tenant=d.get("tenant"),
            created_by=request.user if request.user.is_authenticated else None,
        )
        adhoc_assess.apply_async(args=[job.id], queue="scan")
        return Response(ScanJobSerializer(job).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["get"])
    def findings(self, request, pk=None):
        job = self.get_object()
        data = FindingSerializer(
            job.findings.select_related("cve", "asset", "tenant"), many=True).data
        return Response(data)
