"""
Seed a demo tenant with deliberately messy, realistic inventory — the kind of
strings TRMM/Action1 actually emit — so the matcher gets a fair test:
  - one product with a clean CPE       (high-confidence path)
  - products with vendor/version only  (medium-confidence path)
  - a product whose CVE has no version  (low-confidence -> review path)
  - a product that should match nothing (true negative)
"""
from django.core.management.base import BaseCommand
from core.models import Tenant, Asset, Product


class Command(BaseCommand):
    help = "Seed a demo tenant + assets + inventory for the watch-loop proof."

    def handle(self, *args, **opts):
        Tenant.objects.filter(slug="linskill").delete()
        t = Tenant.objects.create(
            name="Linskill Centre", slug="linskill", scanning_authorised=True
        )

        gw = Asset.objects.create(
            tenant=t, name="vpn-gateway", kind=Asset.Kind.HOST,
            internet_facing=True, target="vpn.example.org",
        )
        fw = Asset.objects.create(
            tenant=t, name="perimeter-fw", kind=Asset.Kind.HOST,
            internet_facing=True, target="fw.example.org",
        )
        wks = Asset.objects.create(
            tenant=t, name="reception-pc", kind=Asset.Kind.HOST,
            internet_facing=False,
        )

        # Internet-facing gateway with a clean CPE -> high-confidence CPE path.
        Product.objects.create(
            asset=gw, vendor="Ivanti", name="Connect Secure", version="21.3",
            cpe="cpe:2.3:a:ivanti:connect_secure:21.3:*:*:*:*:*:*:*", source="manual",
        )
        # Internet-facing firewall, vendor/version only -> medium path, KEV CVE.
        Product.objects.create(
            asset=fw, vendor="Palo Alto Networks", name="PAN-OS", version="11.0.1",
            source="manual",
        )
        # Internal workstation, messy real-world strings -> medium + low paths.
        Product.objects.create(
            asset=wks, vendor="Sage", name="Sage 50 Accounts", version="28.1",
            source="trmm",
        )
        Product.objects.create(
            asset=wks, vendor="Adobe Inc.", name="Adobe Acrobat Reader (64-bit)",
            version="23.006.20320", source="trmm",
        )
        # libcurl bundled, OSS CVE with a range -> medium path.
        Product.objects.create(
            asset=wks, vendor="", name="curl", version="8.1.2", source="trmm",
        )
        # Should match nothing in the fixture set -> true negative.
        Product.objects.create(
            asset=wks, vendor="7-Zip", name="7-Zip", version="23.01", source="trmm",
        )

        self.stdout.write(self.style.SUCCESS(
            f"Seeded {t.name}: {t.assets.count()} assets, "
            f"{Product.objects.filter(asset__tenant=t).count()} products."
        ))
