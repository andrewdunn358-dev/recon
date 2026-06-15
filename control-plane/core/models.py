"""
Recon core data model.

Mirrors §6 of the brief. Multi-tenant from day one (cheap to model now, painful
to retrofit), even though the Phase 0 pilot runs a single tenant. The valuable
join is Product x CVE — see core/matching.py.
"""
from django.conf import settings
from django.db import models
from django.utils import timezone


class Tenant(models.Model):
    """A client org. Same shape as the wifi-portal tenant model."""
    name = models.CharField(max_length=200)
    slug = models.SlugField(unique=True)
    # Stable upstream id (e.g. SynthOps client id) so syncs key on identity, not
    # on a derived slug that can drift and create duplicate tenants.
    external_id = models.CharField(max_length=128, blank=True, default="", db_index=True)
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
    # Stable upstream id (e.g. SynthOps device id) — sync keys on this so a
    # hostname change or re-run can't spawn a duplicate asset.
    external_id = models.CharField(max_length=128, blank=True, default="", db_index=True)
    kind = models.CharField(max_length=16, choices=Kind.choices, default=Kind.HOST)
    # The single most important attribute for prioritisation (§5.4).
    internet_facing = models.BooleanField(default=False)
    target = models.CharField(
        max_length=255, blank=True,
        help_text="Scannable target: hostname/IP/URL. Used by the Nuclei worker.",
    )
    last_seen = models.DateTimeField(null=True, blank=True)
    # Online/offline from the source of truth (SynthOps health check). Lets us
    # flag devices that were unreachable so they can be revisited — their
    # inventory may be stale and they can't be actively scanned while down.
    status = models.CharField(max_length=16, blank=True, default="",
                              help_text="online / offline / unknown, per last SynthOps health check.")
    last_health_check = models.DateTimeField(null=True, blank=True)

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
    references = models.JSONField(default=list, blank=True)  # advisory/patch URLs

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
    # Remediation pointers. For scan findings these come from the Nuclei template;
    # for CVE findings we also derive authoritative links from the CVE.
    references = models.JSONField(default=list, blank=True)
    remediation = models.TextField(blank=True)

    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    notified = models.BooleanField(default=False)
    # Set when a finding came from a dashboard-triggered scan, so the panel can
    # stream this run's findings live.
    scan_job = models.ForeignKey("ScanJob", on_delete=models.SET_NULL, null=True,
                                 blank=True, related_name="findings")

    class Meta:
        ordering = ["priority"]

    def __str__(self):
        return f"{self.label} on {self.asset} [{self.priority}]"

    @property
    def label(self):
        """What to call this finding — CVE id, else template/title."""
        if self.cve_id:
            return self.cve_id
        return self.template_id or self.title or "finding"

    @property
    def remediation_links(self):
        """
        A curated list of {label, url} pointing at fix guidance. CVE findings get
        authoritative deep links (NVD / CVE.org / KEV) plus the CVE's own advisory
        references; scan findings get the Nuclei template's references.
        """
        out, seen = [], set()

        def add(label, url):
            if url and url not in seen:
                seen.add(url)
                out.append({"label": label, "url": url})

        if self.cve_id:
            add("NVD", f"https://nvd.nist.gov/vuln/detail/{self.cve_id}")
            add("CVE.org", f"https://www.cve.org/CVERecord?id={self.cve_id}")
            if self.cve and self.cve.in_kev:
                add("CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
            for url in (self.cve.references if self.cve else [])[:4]:
                add("advisory", url)

        for url in (self.references or [])[:4]:
            add("reference", url)
        return out


class CveProductToken(models.Model):
    """
    Inverted index: one row per (CVE, affected-product token). Lets the matcher
    pull candidate CVEs for a product by token overlap instead of scanning the
    whole CVE table — essential once the full cvelistV5 corpus (~250k+) is loaded.

    The token is the normalised affected-product name (matching.tokens), which is
    exactly the gate match_product_to_cve applies, so the candidate set it yields
    is the same set the matcher would have kept after a full scan.
    """
    cve = models.ForeignKey(CVE, on_delete=models.CASCADE, related_name="product_tokens")
    token = models.CharField(max_length=64, db_index=True)

    class Meta:
        indexes = [models.Index(fields=["token"])]
        constraints = [
            models.UniqueConstraint(fields=["cve", "token"], name="uniq_cve_token"),
        ]

    def __str__(self):
        return f"{self.cve_id}:{self.token}"


class ScanJob(models.Model):
    """
    A user-triggered ad-hoc assessment from the dashboard. The web app creates it
    and enqueues the work to the scan queue (the scan-worker has the tools); the
    worker updates status/summary here, and the page polls this row. Also serves
    as an audit trail of who scanned what, when — useful for §11 records.
    """
    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        DONE = "done", "Done"
        FAILED = "failed", "Failed"

    tenant = models.ForeignKey(Tenant, on_delete=models.SET_NULL, null=True, blank=True,
                               related_name="scan_jobs")
    target = models.CharField(max_length=255)
    do_ports = models.BooleanField(default=False)
    do_nuclei = models.BooleanField(default=True)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.QUEUED)
    phase = models.CharField(max_length=120, blank=True)   # human-readable current step
    progress = models.IntegerField(default=0)              # e.g. hosts scanned
    total = models.IntegerField(default=0)                 # e.g. hosts to scan
    summary = models.TextField(blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
                                   null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.target} [{self.status}]"
