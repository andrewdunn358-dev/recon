"""
Tactical RMM API client (§4.1 — Recon consumes the agent you already deploy).

Endpoints confirmed against the official TRMM docs:
  GET /agents/?detail=false        -> list agents (client_name, site_name, hostname, agent_id)
  GET /software/{agent_id}/        -> installed software for an agent
  GET /clients/                    -> client orgs
Auth is the X-API-KEY header. Create a key in TRMM:
  Settings > Global Settings > API Keys  (its permissions follow the chosen user's role).

Config via env (injected from .env by compose):
  TRMM_API_URL   e.g. https://api.yourrmm.example.com
  TRMM_API_KEY   the X-API-KEY value
"""
from __future__ import annotations

import os


class TRMMError(Exception):
    pass


def _cfg():
    url = os.environ.get("TRMM_API_URL", "").rstrip("/")
    key = os.environ.get("TRMM_API_KEY", "")
    if not url or not key:
        raise TRMMError("Set TRMM_API_URL and TRMM_API_KEY in .env to enable the TRMM sync.")
    return url, key


def _get(path: str):
    import requests
    url, key = _cfg()
    r = requests.get(
        f"{url}{path}",
        headers={"Content-Type": "application/json", "X-API-KEY": key},
        timeout=45,
    )
    r.raise_for_status()
    return r.json()


def list_agents() -> list[dict]:
    """All agents, lightweight. Each has agent_id, hostname, client_name, site_name."""
    return _get("/agents/?detail=false") or []


def get_software(agent_id: str) -> list[dict]:
    """Installed software for one agent. Tolerant of list vs {'software': [...]} shapes."""
    data = _get(f"/software/{agent_id}/")
    if isinstance(data, dict):
        return data.get("software") or []
    return data or []


def normalise_software(sw: dict) -> dict:
    """Pull vendor/name/version out of a TRMM software row, tolerant of field names."""
    name = sw.get("name") or sw.get("DisplayName") or sw.get("displayName") or ""
    version = sw.get("version") or sw.get("DisplayVersion") or sw.get("displayVersion") or ""
    vendor = sw.get("publisher") or sw.get("Publisher") or sw.get("vendor") or ""
    return {"vendor": vendor[:200], "name": name[:200], "version": version[:100]}


# ---- remediation (write path) -------------------------------------------------
# Pushing a fix runs a SAVED TRMM script (audited, controllable) rather than raw
# commands. Set up one script in TRMM (e.g. "Recon Remediate" that takes a package
# id and runs `winget upgrade <id>`), then point Recon at it:
#   REMEDIATION_ENABLED=true            # master off-switch (default off)
#   TRMM_REMEDIATE_SCRIPT_ID=<pk>       # the saved script's id in TRMM
# Endpoint shape can vary by TRMM version — verify on your box before enabling.

def remediation_enabled() -> bool:
    return os.environ.get("REMEDIATION_ENABLED", "false").lower() in ("1", "true", "yes")


def run_script(agent_id: str, args=None, timeout: int = 120) -> dict:
    """Trigger the configured remediation script on one agent and wait for output."""
    import requests
    url, key = _cfg()
    script_id = os.environ.get("TRMM_REMEDIATE_SCRIPT_ID", "")
    if not script_id:
        raise TRMMError("Set TRMM_REMEDIATE_SCRIPT_ID to the saved TRMM script's id.")
    body = {"script": int(script_id), "args": args or [], "output": "wait",
            "timeout": timeout, "run_as_user": False}
    r = requests.post(
        f"{url}/agents/{agent_id}/runscript/",
        headers={"Content-Type": "application/json", "X-API-KEY": key},
        json=body, timeout=timeout + 30,
    )
    r.raise_for_status()
    try:
        return {"ok": True, "result": r.json()}
    except ValueError:
        return {"ok": True, "result": r.text}
