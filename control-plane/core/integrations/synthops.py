"""
SynthOps API client. Recon reads its single source of truth — clients (tenants),
servers/workstations (assets) and per-agent software (products) — straight from
the SynthOps FastAPI, retiring Recon's own direct TRMM pull.

SynthOps already aggregates TRMM, so Recon reads it once from SynthOps rather than
hitting TRMM separately. Auth is JWT:
    POST /api/auth/login {email, password} -> {access_token}; then Bearer header.

Config (env, set in Recon's .env):
    SYNTHOPS_URL       e.g. https://synthops.internal
    SYNTHOPS_USER      a dedicated SynthOps user for Recon (email or username)
    SYNTHOPS_PASSWORD
"""
import os

import requests

SYNTHOPS_URL = os.environ.get("SYNTHOPS_URL", "").rstrip("/")
SYNTHOPS_USER = os.environ.get("SYNTHOPS_USER", "")
SYNTHOPS_PASSWORD = os.environ.get("SYNTHOPS_PASSWORD", "")
# Internal hosts (e.g. *.local) often present a self-signed / internal-CA cert.
# Set SYNTHOPS_VERIFY_SSL=false to skip verification on a trusted LAN, or point
# SYNTHOPS_CA_BUNDLE at your internal CA file to verify properly.
_verify_env = os.environ.get("SYNTHOPS_VERIFY_SSL", "true").lower()
SYNTHOPS_VERIFY = os.environ.get("SYNTHOPS_CA_BUNDLE") or (
    _verify_env not in ("false", "0", "no"))
TIMEOUT = 30
SOFTWARE_TIMEOUT = 12  # fail fast on offline agents so a few duds don't stall a sync

if SYNTHOPS_VERIFY is False:
    # Quiet the warning we'd otherwise emit on every call.
    try:
        from urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore
    except Exception:
        pass


class SynthOpsError(RuntimeError):
    pass


def _as_list(payload):
    """SynthOps list endpoints return bare arrays; the per-agent software endpoint
    wraps it as {"id":.., "software":[...]}. Tolerate both."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("software", "items", "results", "data",
                    "clients", "servers", "workstations"):
            if isinstance(payload.get(key), list):
                return payload[key]
    return []


class SynthOps:
    def __init__(self, base=None, user=None, password=None):
        self.base = (base or SYNTHOPS_URL).rstrip("/")
        self.user = user or SYNTHOPS_USER
        self.password = password or SYNTHOPS_PASSWORD
        self.token = None

    def _api(self, path):
        return f"{self.base}/api{path}"

    def login(self):
        if not self.base:
            raise SynthOpsError("SYNTHOPS_URL is not set")
        if not self.user or not self.password:
            raise SynthOpsError("SYNTHOPS_USER / SYNTHOPS_PASSWORD not set")
        r = requests.post(self._api("/auth/login"),
                          json={"email": self.user, "password": self.password},
                          timeout=TIMEOUT, verify=SYNTHOPS_VERIFY)
        if r.status_code != 200:
            raise SynthOpsError(f"SynthOps login failed ({r.status_code})")
        self.token = (r.json() or {}).get("access_token")
        if not self.token:
            raise SynthOpsError("SynthOps login returned no access_token")
        return self.token

    def _get(self, path, params=None, timeout=None):
        if not self.token:
            self.login()
        headers = {"Authorization": f"Bearer {self.token}"}
        to = timeout or TIMEOUT
        r = requests.get(self._api(path), params=params, headers=headers,
                         timeout=to, verify=SYNTHOPS_VERIFY)
        if r.status_code == 401:  # token expired — re-login once and retry
            self.login()
            headers = {"Authorization": f"Bearer {self.token}"}
            r = requests.get(self._api(path), params=params, headers=headers,
                             timeout=to, verify=SYNTHOPS_VERIFY)
        r.raise_for_status()
        return r.json()

    # ---- resources --------------------------------------------------------
    def clients(self):
        return _as_list(self._get("/clients"))

    def servers(self, client_id=None):
        return _as_list(self._get("/servers", {"client_id": client_id} if client_id else None))

    def workstations(self, client_id=None):
        return _as_list(self._get("/workstations", {"client_id": client_id} if client_id else None))

    def agent_software(self, agent_id):
        """Installed software for a device's TRMM agent (TRMM-native rows).
        Best-effort + short timeout: a failing/offline agent returns [] fast
        rather than stalling a whole-estate sync."""
        try:
            return _as_list(self._get(
                f"/integrations/trmm/agent/{agent_id}/software", timeout=SOFTWARE_TIMEOUT))
        except Exception:
            return []
