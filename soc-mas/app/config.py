"""Runtime configuration for the SOC IR multi-agent demo.

Two backends behind the same UI/SSE contract:

  * inprocess  (default) - agents run in-process; LLM via the CalypsoAI proxy,
                and the OAuth-scope / capability / A2A-card decisions are
                reproduced in Python. Falls back to a mock brain with no creds.
  * distributed         - agents run their real loops against the live lab
                stack: real Keycloak client_credentials tokens, a real MCP SSE
                session (real capability manifest + scope + Postgres), and a
                real A2A HTTP call to the Comms container. Enforcement is done
                by those services, not by this app. Set BACKEND=distributed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

try:  # load a local .env if present (optional dependency)
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    pass


def _env(*names: str, default: str | None = None) -> str | None:
    for n in names:
        v = os.environ.get(n)
        if v:
            return v
    return default


@dataclass(frozen=True)
class Settings:
    app_name: str = "SOC IR Multi-Agent Demo"

    # backend: "inprocess" | "distributed"
    backend: str = "inprocess"

    # F5 AI Security (CalypsoAI) OpenAI-compatible proxy (used by both backends).
    proxy_base_url: str | None = None
    proxy_token: str | None = None
    model: str = "gpt-4o-mini"
    mock_mode: bool = True

    # ---- distributed backend: live lab endpoints ----
    keycloak_issuer: str = "http://keycloak:8080/realms/agent-lab"
    mcp_server_url: str = "http://mcp-server:8000/sse"
    comms_a2a_url: str = "http://comms:9100"

    # ---- agents_http backend (C1): the shimmed agent services ----
    triage_url: str = "http://triage:9200"
    threat_intel_url: str = "http://threat-intel:9200"
    remediation_url: str = "http://remediation:9200"

    # per-agent Keycloak client credentials (service accounts)
    triage_client_id: str = "agent-triage"
    triage_secret: str = "agent-triage-secret-change-me"
    threat_intel_client_id: str = "agent-threat-intel"
    threat_intel_secret: str = "agent-threat-intel-secret-change-me"
    remediation_client_id: str = "agent-remediation"
    remediation_secret: str = "agent-remediation-secret-change-me"

    @classmethod
    def from_env(cls) -> "Settings":
        backend = (os.environ.get("BACKEND", "inprocess") or "inprocess").lower()
        base = _env("CALYPSOAI_OPENAI_API_BASE", "CALYPSOAI_BASE_URL")
        token = _env("CALYPSOAI_TOKEN", "CALYPSOAI_PROJECT_TOKEN")
        model = os.environ.get("CALYPSOAI_MODEL", "gpt-4o-mini")

        # distributed / agents_http talk to real services (never mock).
        if backend in ("distributed", "agents_http"):
            mock = False
        else:
            forced_mock = os.environ.get("MOCK_MODE", "").lower() in ("1", "true", "yes")
            mock = forced_mock or not (base and token)

        return cls(
            backend=backend,
            proxy_base_url=base.rstrip("/") if base else None,
            proxy_token=token,
            model=model,
            mock_mode=mock,
            keycloak_issuer=os.environ.get("KEYCLOAK_ISSUER", cls.keycloak_issuer).rstrip("/"),
            mcp_server_url=os.environ.get("MCP_SERVER_URL", cls.mcp_server_url),
            comms_a2a_url=os.environ.get("COMMS_A2A_URL", cls.comms_a2a_url).rstrip("/"),
            triage_url=os.environ.get("TRIAGE_URL", cls.triage_url).rstrip("/"),
            threat_intel_url=os.environ.get("THREAT_INTEL_URL", cls.threat_intel_url).rstrip("/"),
            remediation_url=os.environ.get("REMEDIATION_URL", cls.remediation_url).rstrip("/"),
            triage_client_id=_env("TRIAGE_OAUTH_CLIENT_ID", default=cls.triage_client_id),
            triage_secret=_env("TRIAGE_OAUTH_CLIENT_SECRET", default=cls.triage_secret),
            threat_intel_client_id=_env("THREAT_INTEL_OAUTH_CLIENT_ID", default=cls.threat_intel_client_id),
            threat_intel_secret=_env("THREAT_INTEL_OAUTH_CLIENT_SECRET", default=cls.threat_intel_secret),
            remediation_client_id=_env("REMEDIATION_OAUTH_CLIENT_ID", default=cls.remediation_client_id),
            remediation_secret=_env("REMEDIATION_OAUTH_CLIENT_SECRET", default=cls.remediation_secret),
        )


settings = Settings.from_env()
