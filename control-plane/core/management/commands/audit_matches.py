"""
Systematically surface where the matcher is resting on weak ground, so we find
whole classes of false positive at once instead of one screenshot at a time.

For every CVE-backed watch finding it recomputes the distinctive tokens shared
between the installed product name and the CVE's affected product name(s) — the
"anchor" of the match — and reports:

  1. ANCHOR TOKENS that carry the most matches, especially matches resting on a
     SINGLE shared token. A token anchoring thousands of findings on its own
     (e.g. "web", "hub", "agent") is almost certainly generic — a stopword
     candidate. This is how we find the next "web" before it's spotted by eye.
  2. SINGLE-ANCHOR share — how much of the worklist hangs on one token.
  3. Highest fan-out CVEs (one CVE -> many devices) and products (one product ->
     many CVEs): the outliers most likely to be coincidental.
  4. NAME-MISMATCH matches: the installed product and the advisory product share
     a token but their distinctive names differ (the Sophos / Azure-Stack-Hub
     signature) — the pile to verify and dismiss.

Read-only. Run:  python manage.py audit_matches
Options:  --limit N (rows per table, default 30)  --single-only  --token TOKEN
"""
from collections import Counter, defaultdict

from django.core.management.base import BaseCommand

from core.matching import candidate_tokens, normalise


class Command(BaseCommand):
    help = "Audit watch findings for weak/generic-token matches (read-only)."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=30)
        parser.add_argument("--single-only", action="store_true",
                            help="Only consider findings anchored on a single token.")
        parser.add_argument("--token", type=str, default="",
                            help="Drill in: list CVEs+products anchored by this token.")

    def handle(self, *args, **opts):
        from core.models import Finding, CVE

        limit = opts["limit"]
        single_only = opts["single_only"]
        drill = normalise(opts["token"]).strip()

        # Cache each CVE's affected distinctive tokens once.
        aff_tokens: dict[str, frozenset] = {}
        for cid, affected in CVE.objects.values_list("cve_id", "affected"):
            toks = set()
            for aff in affected or []:
                toks |= candidate_tokens(aff.get("product", ""))
            aff_tokens[cid] = frozenset(toks)

        qs = (Finding.objects.filter(source="watch", cve__isnull=False,
                                     product__isnull=False)
              .values_list("cve_id", "product__name", "asset_id", "priority",
                           "cve__in_kev"))

        total = single = 0
        # anchor token -> stats
        tok_findings = Counter()
        tok_single = Counter()
        tok_cves = defaultdict(set)
        tok_products = defaultdict(set)
        # fan-out
        cve_devices = defaultdict(set)
        product_cves = defaultdict(set)
        # name-mismatch pile (installed distinctive set != advisory distinctive set)
        mismatch = Counter()
        # drill-down rows
        drill_rows = []

        for cve_id, pname, asset_id, priority, in_kev in qs.iterator(chunk_size=5000):
            p_ct = candidate_tokens(pname)
            shared = p_ct & aff_tokens.get(cve_id, frozenset())
            if not shared:
                continue  # shouldn't happen for a real finding, but be safe
            is_single = len(shared) == 1
            if single_only and not is_single:
                continue

            total += 1
            single += int(is_single)
            cve_devices[cve_id].add(asset_id)
            product_cves[normalise(pname)].add(cve_id)
            # the installed name carries tokens the advisory's didn't -> different product
            if p_ct and shared != p_ct:
                mismatch[(normalise(pname), cve_id)] += 1

            for t in shared:
                tok_findings[t] += 1
                if is_single:
                    tok_single[t] += 1
                tok_cves[t].add(cve_id)
                tok_products[t].add(normalise(pname))

            if drill and drill in shared:
                drill_rows.append((cve_id, pname, in_kev))

        if total == 0:
            self.stdout.write("No CVE-backed watch findings to audit.")
            return

        def hr(title):
            self.stdout.write("\n" + "=" * 76 + f"\n{title}\n" + "-" * 76)

        self.stdout.write(
            f"Audited {total} CVE-backed watch findings — "
            f"{single} ({100*single//max(total,1)}%) rest on a SINGLE shared token.")

        if drill:
            hr(f"Findings anchored by token '{drill}'  ({len(drill_rows)})")
            for cid, pname, kev in sorted(drill_rows)[:limit]:
                self.stdout.write(f"  {cid}{' [KEV]' if kev else ''}  <-  {pname}")
            return

        hr("Generic-anchor suspects — tokens carrying SINGLE-token matches "
           "(stopword candidates)")
        self.stdout.write(
            f"  {'token':<22}{'single':>8}{'total':>8}{'#CVEs':>8}{'#products':>11}")
        for t, n in tok_single.most_common(limit):
            self.stdout.write(
                f"  {t:<22}{n:>8}{tok_findings[t]:>8}"
                f"{len(tok_cves[t]):>8}{len(tok_products[t]):>11}")

        hr("Highest fan-out CVEs (one CVE -> many devices)")
        for cid, devs in sorted(cve_devices.items(), key=lambda x: -len(x[1]))[:limit]:
            self.stdout.write(f"  {len(devs):>5} devices   {cid}")

        hr("Highest fan-out products (one product -> many distinct CVEs)")
        for pname, cves in sorted(product_cves.items(), key=lambda x: -len(x[1]))[:limit]:
            self.stdout.write(f"  {len(cves):>5} CVEs      {pname}")

        hr("Name-mismatch matches (installed name carries tokens the advisory "
           "didn't — verify/dismiss pile)")
        for (pname, cid), _ in mismatch.most_common(limit):
            self.stdout.write(f"  {cid}  <-  {pname}")

        self.stdout.write(
            "\nNext steps: tokens high in the first table with many #CVEs and "
            "#products are generic — tell me and they become stopwords. Drill any "
            "with  --token <name>.  Fan-out outliers are either real (KEV in common "
            "software) or coincidental — spot-check on the audit page.")
