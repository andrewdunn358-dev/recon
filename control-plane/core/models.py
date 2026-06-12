"""
Recon core data model.

Mirrors §6 of the brief. Multi-tenant from day one (cheap to model now, painful
to retrofit), even though the Phase 0 pilot runs a single tenant. The valuable
join is Product x CVE — see core/matching.py.
"""
from django.db import models
from django.utils import timezone


class Tenant(models.Model):
    """A client org. Same shape as the wifi-portal tenant model."""
    name = models.CharField(max_length=200)
    slug = models.SlugField(unique=True)
    # Per-tenant scan authorisation gate (§11). Nothing active runs without this.
    scanning_authorised = models.BooleanField(
        default=False,
        help_text="Written authorisation on file for active scanning of this estate.",
    )
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.name


class Asset(models.Model):
    """A host / IP / domain / web app. §6."""
    class Kind(models.TextChoices):
        HOST = "host", "Host"
        IP = "ip", "IP address"
        DOMAIN = "domain", "Domain"
        WEBAPP = "webapp", "Web application"

    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="assets")
    name = models.CharField(max_length=255)
    kind = models.CharField(max_length=16, choices=Kind.choices, default=Kind.HOST)
    # The single most important attribute for prioritisation (§5.4).
    internet_facing = models.BooleanField(default=False)
    target = models.CharField(
        max_length=255, blank=True,
        help_text="Scannable target: hostname/IP/URL. Used by the Nuclei worker.",
    )
    last_seen = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.name} ({self.tenant.slug})"


class Product(models.Model):
    """
    Software + version running on an asset (from agent inventory).
    Maps to CPE where possible — but post-§5.1 most CVEs lack CPEs, so we keep
    raw vendor/name/version and let the matcher fall back to token matching.
    """
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="products")
    vendor = models.CharField(max_length=200, blank=True)
    name = models.CharField(max_length=200)
    version = models.CharField(max_length=100, blank=True)
    # Best-effort CPE 2.3 string. Often empty — that's the whole problem.
    cpe = models.CharField(max_length=400, blank=True)
    source = models.CharField(
        max_length=50, blank=True,
        help_text="Where this inventory row came from: trmm, action1, manual, wazuh.",
    )

    def __str__(self):
        v = f" {self.version}" if self.version else ""
        return f"{self.vendor} {self.name}{v}".strip()


class CVE(models.Model):
    """
    A vulnerability record, assembled from the multi-source feed mix (§5.2).
    Never trust a single source — KEV/EPSS/Vulnrichment enrich the raw record.
    """
    cve_id = models.CharField(max_length=24, primary_key=True)  # CVE-YYYY-NNNNN
    title = models.CharField(max_length=500, blank=True)
    summary = models.TextField(blank=True)

    # Enrichment signals — these drive prioritisation (§5.4).
    in_kev = models.BooleanField(default=False)  # CISA KEV: exploited right now
    kev_date_added = models.DateField(null=True, blank=True)
    epss = models.FloatField(null=True, blank=True)  # 0..1 exploitation probability
    cvss = models.FloatField(null=True, blank=True)  # base score, treated as noisy
    cwe = models.CharField(max_length=32, blank=True)

    # Structured affected-product data for matching. List of dicts:
    # {"vendor":..., "product":..., "cpe":..., "versions":[{...range...}]}
    affected = models.JSONField(default=list, blank=True)

    sources = models.JSONField(default=list, blank=True)  # provenance
    published = models.DateField(null=True, blank=True)
    last_modified = models.DateTimeField(default=timezone.now)

    class Meta:
        indexes = [
            models.Index(fields=["in_kev"]),
            models.Index(fields=["epss"]),
        ]

    def __str__(self):
        flag = " [KEV]" if self.in_kev else ""
        return f"{self.cve_id}{flag}"


class WatchSubscription(models.Model):
    """
    Tenant <-> vendor/product they actually run. Drives the watch list.
    The OpenCVE concept (§5.3), implemented in-house to keep the IP owned.
    """
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="watches")
    vendor = models.CharField(max_length=200, blank=True)
    product = models.CharField(max_length=200, blank=True)

    def __str__(self):
        return f"{self.tenant.slug} watches {self.vendor} {self.product}".strip()


class Finding(models.Model):
    """
    A vuln instance: asset + CVE + severity + status. §6.
    (DefectDojo owns most of this if/when it's introduced in Phase 1.)
    """
    class Status(models.TextChoices):
        OPEN = "open", "Open"
        TRIAGED = "triaged", "Triaged"
        FIXED = "fixed", "Fixed"
        ACCEPTED = "accepted", "Risk accepted"

    class Priority(models.TextChoices):
        CRITICAL = "P1", "P1 — Critical (KEV)"
        HIGH = "P2", "P2 — High (likely exploited / exposed)"
        MEDIUM = "P3", "P3 — Medium"
        LOW = "P4", "P4 — Low"
        REVIEW = "P?", "P? — Needs human review"

    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="findings")
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name="findings")
    product = models.ForeignKey(
        Product, on_delete=models.SET_NULL, null=True, blank=True, related_name="findings"
    )
    # Nullable now: an active-scan finding (exposed panel, misconfig) often has
    # no CVE. The brief models a finding as "asset + CVE/template" (§6).
    cve = models.ForeignKey(
        CVE, on_delete=models.CASCADE, null=True, blank=True, related_name="findings"
    )

    # Where this finding came from, and how to describe it when there's no CVE.
    source = models.CharField(max_length=16, default="watch")   # watch | nuclei
    title = models.CharField(max_length=400, blank=True)
    severity = models.CharField(max_length=16, blank=True)      # nuclei severity
    template_id = models.CharField(max_length=200, blank=True)  # nuclei template
    matched_at = models.CharField(max_length=400, blank=True)   # url/host:port hit

    priority = models.CharField(max_length=2, choices=Priority.choices, default=Priority.REVIEW)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.OPEN)

    # How confident the Product x CVE match was. Low-confidence => human review.
    match_confidence = models.CharField(max_length=10, blank=True)  # high/medium/low
    match_reason = models.CharField(max_length=300, blank=True)

    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    notified = models.BooleanField(default=False)

    class Meta:
        ordering = ["priority"]

    def __str__(self):
        return f"{self.label} on {self.asset} [{self.priority}]"

    @property
    def cve_id(self):
        return self.cve.cve_id if self.cve else ""

    @property
    def label(self):
        """What to call this finding — CVE id, else template/title."""
        if self.cve:
            return self.cve.cve_id
        return self.template_id or self.title or "finding"
