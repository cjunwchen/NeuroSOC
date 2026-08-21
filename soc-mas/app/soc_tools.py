"""SOC investigation + remediation toolkit, ported in-process from the lab's
MCP server (mcp_server/server.py, auth.py, capabilities.py).

The two authorization layers the lab teaches are preserved here as plain code
so the same denials happen without Keycloak or an MCP server:

  * Capability manifest (identity-based): which agent may see/call a tool.
  * OAuth scope    (action-based):        whether a specific call is allowed.
                                          execute_db_query resolves its scope
                                          per-SQL-verb, so the Remediation
                                          agent (read+write, NOT admin) can run
                                          SELECT/UPDATE but a DROP is denied.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import httpx

# --------------------------------------------------------------------------
# Simulated SOC data (verbatim from the lab's MCP server)
# --------------------------------------------------------------------------
KNOWN_MALICIOUS_IPS = {
    "185.220.101.45": {"threat": "Tor Exit Node", "confidence": 90},
    "192.42.116.16": {"threat": "Port Scanning", "confidence": 75},
    "45.33.32.156": {"threat": "Known C2 Server", "confidence": 88},
    "198.199.10.1": {"threat": "Brute Force Source", "confidence": 72},
    "89.248.167.131": {"threat": "Malware Distribution", "confidence": 95},
}

SIMULATED_ALERTS = [
    {"id": "ALT-001", "timestamp": "2024-01-15T10:23:00Z", "source_ip": "185.220.101.45",
     "destination_ip": "10.0.1.22", "event_type": "SSH Brute Force", "severity": "HIGH", "attempts": 847},
    {"id": "ALT-002", "timestamp": "2024-01-15T10:25:00Z", "source_ip": "192.168.1.105",
     "destination_ip": "10.0.1.5", "event_type": "Port Scan", "severity": "MEDIUM", "attempts": 12},
    {"id": "ALT-003", "timestamp": "2024-01-15T10:27:00Z", "source_ip": "45.33.32.156",
     "destination_ip": "10.0.1.44", "event_type": "Suspicious Outbound Connection", "severity": "HIGH", "attempts": 3},
    {"id": "ALT-004", "timestamp": "2024-01-15T10:30:00Z", "source_ip": "10.0.0.52",
     "destination_ip": "8.8.8.8", "event_type": "Unusual DNS Volume", "severity": "MEDIUM", "attempts": 1203},
    {"id": "ALT-005", "timestamp": "2024-01-15T10:31:00Z", "source_ip": "89.248.167.131",
     "destination_ip": "10.0.1.10", "event_type": "Possible Data Exfiltration", "severity": "CRITICAL", "attempts": 1},
]

# Offline fallback geolocation for the known IPs (used when ip-api.com is
# unreachable, so the demo never hangs on a network call).
_GEO_FALLBACK = {
    "185.220.101.45": {"country": "Germany", "region": "Hesse", "city": "Frankfurt",
                       "isp": "Tor", "org": "Tor Exit", "as": "AS205100"},
}

# --------------------------------------------------------------------------
# Authorization model (from mcp_server/auth.py + capabilities.json + Keycloak)
# --------------------------------------------------------------------------
# Scopes each agent's OAuth client is granted. Triage has none (it never
# touches tools); Threat-Intel is read-only; Remediation has read+write but
# deliberately NOT admin -- that gap is what blocks the destructive DROP.
AGENT_SCOPES: dict[str, set[str]] = {
    "agent-triage": set(),
    "agent-threat-intel": {"mcp:read"},
    "agent-remediation": {"mcp:read", "mcp:write"},
}

# Per-agent capability manifest (mcp_server/capabilities.json).
CAPABILITIES: dict[str, list[str]] = {
    "agent-threat-intel": [
        "get_recent_alerts", "get_alert_details", "check_ip_reputation", "lookup_ip_geolocation",
    ],
    "agent-remediation": [
        "get_recent_alerts", "get_alert_details", "execute_db_query", "quarantine_host", "revoke_credential",
    ],
}

_ADMIN_VERBS = {"DROP", "TRUNCATE", "ALTER", "CREATE", "GRANT", "REVOKE"}
_WRITE_VERBS = {"INSERT", "UPDATE", "DELETE"}


def scope_for_sql(sql: str) -> str:
    """Resolve the OAuth scope a SQL statement requires (lab's auth.scope_for_sql).

    SELECT -> mcp:read, INSERT/UPDATE/bounded-DELETE -> mcp:write,
    DROP/TRUNCATE/ALTER/CREATE and unbounded DELETE -> mcp:admin.
    """
    s = (sql or "").strip().rstrip(";").lstrip()
    verb = s.split(None, 1)[0].upper() if s else ""
    if verb in _ADMIN_VERBS:
        return "mcp:admin"
    if verb == "DELETE" and "where" not in s.lower():
        return "mcp:admin"          # unbounded delete is as destructive as a drop
    if verb in _WRITE_VERBS:
        return "mcp:write"
    if verb == "SELECT":
        return "mcp:read"
    return "mcp:admin"              # unknown -> fail closed to the strictest scope


def _deny(reason: str, **extra) -> str:
    return json.dumps({"error": "forbidden", "reason": reason, **extra}, indent=2)


# --------------------------------------------------------------------------
# In-memory "tickets" table so execute_db_query returns plausible results
# without a real Postgres. (DROP never actually runs -- scope denies it first.)
# --------------------------------------------------------------------------
_TICKETS = [
    {"id": 1, "title": "Investigate SSH brute force on web-prod-01", "status": "open"},
    {"id": 2, "title": "Review outbound C2 connection ALT-003", "status": "open"},
    {"id": 3, "title": "Rotate credentials for svc-deploy", "status": "in_progress"},
]


def _run_sql(sql: str) -> str:
    s = sql.strip().rstrip(";").lstrip()
    verb = s.split(None, 1)[0].upper() if s else ""
    if verb == "SELECT":
        return json.dumps({"executed": sql, "rows_returned": len(_TICKETS),
                           "rows": _TICKETS, "truncated": False}, indent=2, default=str)
    if verb in _WRITE_VERBS:
        return json.dumps({"executed": sql, "status": f"{verb} {len(_TICKETS)}", "ok": True}, indent=2)
    # DDL would land here, but scope gating means we never reach it for the
    # Remediation agent. Kept for completeness.
    return json.dumps({"executed": sql, "status": verb, "ok": True}, indent=2)


# --------------------------------------------------------------------------
# Tool implementations (docstrings are the LLM-facing contract)
# --------------------------------------------------------------------------
async def get_recent_alerts(limit: int = 5) -> str:
    """Retrieve recent security alerts from the SOC log store. Use this first to
    see what events are happening. Returns source IPs, event types, and severity.

    Args: limit: how many recent alerts to return (default 5, max 10)."""
    limit = min(int(limit or 5), 10)
    return json.dumps({"alert_count": min(limit, len(SIMULATED_ALERTS)),
                       "alerts": SIMULATED_ALERTS[:limit]}, indent=2)


async def get_alert_details(alert_id: str) -> str:
    """Get the full detail for one alert by id (e.g. 'ALT-001').

    Args: alert_id: the alert identifier to look up."""
    for a in SIMULATED_ALERTS:
        if a["id"].lower() == str(alert_id).lower():
            return json.dumps({"alert": a}, indent=2)
    return json.dumps({"error": f"no alert with id {alert_id!r}"}, indent=2)


async def check_ip_reputation(ip_address: str) -> str:
    """Check whether an IP is known-bad against threat-intel feeds. Call this for
    any external IP in an alert. Returns is_malicious, threat type, confidence 0-100.

    Args: ip_address: the IPv4 address to check."""
    if ip_address in KNOWN_MALICIOUS_IPS:
        info = KNOWN_MALICIOUS_IPS[ip_address]
        return json.dumps({"ip": ip_address, "is_malicious": True, "threat_type": info["threat"],
                           "confidence_score": info["confidence"],
                           "recommendation": "BLOCK -- high-confidence threat indicator",
                           "checked_at": datetime.now(timezone.utc).isoformat()}, indent=2)
    return json.dumps({"ip": ip_address, "is_malicious": False, "threat_type": "None detected",
                       "confidence_score": 0, "recommendation": "MONITOR -- no known threat indicators",
                       "checked_at": datetime.now(timezone.utc).isoformat()}, indent=2)


async def lookup_ip_geolocation(ip_address: str) -> str:
    """Look up geographic + network ownership for an IP. Useful for spotting
    traffic from unexpected countries or hosting providers.

    Args: ip_address: the IPv4 address to look up."""
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip_address}",
                params={"fields": "status,country,regionName,city,isp,org,as,query"},
            )
            data = resp.json()
        if data.get("status") == "fail":
            raise ValueError("private/reserved")
    except Exception:
        data = _GEO_FALLBACK.get(ip_address)
        if data is None:
            return json.dumps({"ip": ip_address, "error": "geolocation unavailable"}, indent=2)
    return json.dumps({"ip": ip_address, "country": data.get("country", "Unknown"),
                       "region": data.get("regionName", data.get("region", "Unknown")),
                       "city": data.get("city", "Unknown"), "isp": data.get("isp", "Unknown"),
                       "organization": data.get("org", "Unknown"), "asn": data.get("as", "Unknown"),
                       "queried_at": datetime.now(timezone.utc).isoformat()}, indent=2)


async def execute_db_query(sql: str) -> str:
    """Run SQL against the operational database to inspect or repair data.

    Args: sql: a single SQL statement."""
    return _run_sql(sql)


async def quarantine_host(hostname: str, reason: str = "") -> str:
    """Isolate a host from the production network as part of incident response.

    Args: hostname: host/IP to quarantine. reason: short reason (logged)."""
    return json.dumps({"hostname": hostname, "quarantined": True, "reason": reason,
                       "performed_at": datetime.now(timezone.utc).isoformat(),
                       "note": "MOCK: no real network controller wired up"}, indent=2)


async def revoke_credential(principal: str, reason: str = "") -> str:
    """Revoke a user or service credential in the directory.

    Args: principal: user/service to revoke. reason: short reason (logged)."""
    return json.dumps({"principal": principal, "revoked": True, "reason": reason,
                       "performed_at": datetime.now(timezone.utc).isoformat(),
                       "note": "MOCK: no real IdP wired up"}, indent=2)


# name -> (callable, scope-resolver)
_TOOLS = {
    "get_recent_alerts": (get_recent_alerts, lambda a: "mcp:read"),
    "get_alert_details": (get_alert_details, lambda a: "mcp:read"),
    "check_ip_reputation": (check_ip_reputation, lambda a: "mcp:read"),
    "lookup_ip_geolocation": (lookup_ip_geolocation, lambda a: "mcp:read"),
    "execute_db_query": (execute_db_query, lambda a: scope_for_sql(a.get("sql", ""))),
    "quarantine_host": (quarantine_host, lambda a: "mcp:write"),
    "revoke_credential": (revoke_credential, lambda a: "mcp:write"),
}

# Minimal OpenAI function-call schemas for each tool.
_SCHEMAS = {
    "get_recent_alerts": {"limit": {"type": "integer"}},
    "get_alert_details": {"alert_id": {"type": "string"}},
    "check_ip_reputation": {"ip_address": {"type": "string"}},
    "lookup_ip_geolocation": {"ip_address": {"type": "string"}},
    "execute_db_query": {"sql": {"type": "string"}},
    "quarantine_host": {"hostname": {"type": "string"}, "reason": {"type": "string"}},
    "revoke_credential": {"principal": {"type": "string"}, "reason": {"type": "string"}},
}
_REQUIRED = {
    "get_recent_alerts": [], "get_alert_details": ["alert_id"],
    "check_ip_reputation": ["ip_address"], "lookup_ip_geolocation": ["ip_address"],
    "execute_db_query": ["sql"], "quarantine_host": ["hostname"], "revoke_credential": ["principal"],
}


def openai_tool_schemas(client_id: str) -> list[dict]:
    """Capability-filtered tool menu for one agent (the MCP capability manifest)."""
    names = CAPABILITIES.get(client_id, [])
    schemas = []
    for name in names:
        fn = _TOOLS[name][0]
        schemas.append({
            "type": "function",
            "function": {
                "name": name,
                "description": (fn.__doc__ or "").strip().split("\n\n")[0],
                "parameters": {
                    "type": "object",
                    "properties": _SCHEMAS[name],
                    "required": _REQUIRED[name],
                },
            },
        })
    return schemas


async def execute_tool(client_id: str, name: str, args: dict) -> dict:
    """Run one tool with both authorization layers enforced.

    Returns {"result": <text>, "scope": <needed>, "allowed": bool,
             "denied_reason": <str|None>}.
    """
    args = args or {}
    # Layer 1 -- capability manifest (identity).
    if name not in CAPABILITIES.get(client_id, []):
        reason = "tool not in capability manifest for this client"
        return {"result": _deny(reason, client_id=client_id, tool=name),
                "scope": None, "allowed": False, "denied_reason": reason}

    if name not in _TOOLS:
        return {"result": _deny(f"unknown tool {name!r}"), "scope": None,
                "allowed": False, "denied_reason": "unknown tool"}

    fn, scope_of = _TOOLS[name]
    needed = scope_of(args)

    # Layer 2 -- OAuth scope (action).
    if needed not in AGENT_SCOPES.get(client_id, set()):
        reason = f"insufficient scope: {name} needs {needed}"
        return {"result": _deny(reason, client_id=client_id, tool=name, needed_scope=needed,
                                granted_scopes=sorted(AGENT_SCOPES.get(client_id, set()))),
                "scope": needed, "allowed": False, "denied_reason": reason}

    result = await fn(**args)
    return {"result": result, "scope": needed, "allowed": True, "denied_reason": None}
