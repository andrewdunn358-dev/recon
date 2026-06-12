# Recon — Phase 0 (watch-loop proof)

Self-hosted continuous vulnerability management for the Synthesis IT MSP client
base. This repo is **Phase 0** from the project brief: single-tenant,
external-focused, built to prove one loop end to end —

> **a new CVE → matched to a product a client actually runs → a prioritised alert.**

Everything else in the brief (Greenbone, DefectDojo, on-site collectors,
multi-tenant dashboards, AI triage) is deliberately deferred. This is the
smallest thing that proves the core IP works.

---

## What's in here

```
recon/
├── docker-compose.yml        # single-box Phase 0 stack
├── .env.example              # copy to .env
├── control-plane/            # the Django app — the product
│   ├── core/
│   │   ├── models.py         # Tenant, Asset, Product, CVE, WatchSubscription, Finding (§6)
│   │   ├── matching.py       # Product × CVE matcher — THE core IP (§6)
│   │   ├── prioritise.py     # exploitation-led ranking (§5.4)
│   │   ├── feeds/            # KEV / EPSS / cvelistV5 / Vulnrichment / OSV (§5.2)
│   │   ├── tasks.py          # nightly orchestration as Celery tasks (§7)
│   │   ├── fixtures/         # sample feed data so the loop runs offline
│   │   └── management/commands/
│   │       ├── seed_demo.py      # realistic messy inventory
│   │       └── run_watch_loop.py # the end-to-end proof
│   └── ...
└── scan-worker/              # Nuclei worker (separate image, see §4.2)
```

## The bit that matters: `core/matching.py`

The brief's "valuable join" is Product × CVE. The hard part — flagged before any
code was written — is that since the **NVD triage change (15 Apr 2026, §5.1)**,
~80% of new CVEs ship **without clean CPE data**. A CPE-only matcher would
silently miss most of what's published.

So the matcher runs three paths and **scores its own confidence**:

| Path | When | Confidence | Outcome |
|------|------|-----------|---------|
| CPE compare | both sides have a CPE | **high** | finding raised |
| vendor+product token + version-range | no CPE, but version data exists | **medium** | finding raised |
| vendor+product token, version absent | CVE record has no usable versions | **low** | **P? — human review** |

Low-confidence matches are never dropped and never auto-fired — they go to a
logged-in human (the advisory-only posture, §4.3). Better a human glances at a
maybe than the loop silently misses a live CVE.

## Prioritisation: `core/prioritise.py`

Exploitation-led, **not** CVSS-led (§5.4):

- in **KEV** → **P1** (exploited right now)
- high **EPSS** *and* internet-facing → **P2**
- high EPSS *or* internet-facing high-CVSS → **P3**
- else → **P4**
- low-confidence match → **P?** regardless of score

---

## Run the proof locally (no Docker, no network)

```bash
cd control-plane
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
export CELERY_EAGER=1
python manage.py migrate
python manage.py seed_demo
python manage.py run_watch_loop
```

You'll get a prioritised findings table: two P1s (Ivanti + PAN-OS, both in KEV,
one matched by CPE and one by version-range fallback), two P3s, and one P? that
correctly bounced to human review because its CVE record had no version data.

## Run on your box (Docker)

```bash
cp .env.example .env      # then edit secrets
docker compose up -d --build
docker compose exec web python manage.py migrate
docker compose exec web python manage.py createsuperuser
```

Admin is the Phase 0 UI at `/admin/`; a plain prioritised board is at `/`.

On the deployed box the real feeds (cisa.gov, first.org, GitHub) are reachable,
so wire the fetch in `core/tasks.feed_pull` (the integration point is marked) and
drop `use_fixtures=True`. The sandbox used fixtures only because those domains
weren't reachable there.

---

## Open decisions still live (brief §12)

- **Watch engine**: this scaffold implements matching **in-house** to keep the IP
  owned and prove the loop. **OpenCVE** (§5.3) remains a drop-in alternative —
  run it as a container and feed its webhooks into the same pipeline.
- **DefectDojo**: deferred to Phase 1 (ingest/dedupe). Not needed to prove the loop.
- **Greenbone**: deferred to Phase 1 (the resource hog; fiddly in Docker).
- **Primary RMM inventory source** (TRMM vs Action1) for the `Product` feed.
- **Name** — "Recon" is still a placeholder.

## Safety posture baked in (brief §11)

- `Tenant.scanning_authorised` gates all active scanning. `nuclei_scan` aborts
  without it.
- AI / automation is **advisory only** — nothing runs against a device without
  explicit human sign-off. No closed-loop action, ever.
- Scan worker is a separate image precisely so its egress can be moved to a
  clean, disposable IP later (don't scan from your office business line at scale).
