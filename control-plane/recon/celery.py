import os
from celery import Celery
from celery.schedules import crontab

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "recon.settings")
app = Celery("recon")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()

# Nightly orchestration schedule (§7). Times are placeholders — keep active
# scans inside agreed client windows (§11).
app.conf.beat_schedule = {
    "nightly-cve-mirror": {
        "task": "core.tasks.update_cve_mirror",
        "schedule": crontab(hour=1, minute=30),
    },
    "nightly-feed-pull": {
        "task": "core.tasks.feed_pull",
        "schedule": crontab(hour=2, minute=0),
    },
    "nightly-watch-loop": {
        "task": "core.tasks.watch_loop",
        "schedule": crontab(hour=2, minute=30),
    },
}
