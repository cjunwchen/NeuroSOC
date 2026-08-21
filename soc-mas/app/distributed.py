"""Distributed backend: run the agents' real loops against the live lab stack.

Same public shape as agents.py (run_tool_agent / run_comms), and it emits the
same SSE events, so the UI is unchanged. The difference is that the security
decisions are made by the real services:

  * threat-intel / remediation -> real Keycloak client_credentials token ->
    real MCP server over SSE. The MCP server applies its capability manifest
    (Module 2) and per-call OAuth scope (Slice B), and execute_db_query hits
    real Postgres. Denials come back as {"error": "forbidden", ...}.
  * comms -> real A2A HTTP POST to the Comms container with an agent-triage
    token; Comms introspects the token and enforces its agent-card
    allowed_callers / approval_required. A 403 is a real deny.

Triage stays in agents.run_triage (pure LLM planning via the proxy) in both
backends.
"""

from __future__ import annotations

import json
from typing import Awaitable, Callable

import httpx

from .config import settings
from . import agents, soc_tools

Emit = Callable[[str, dict], Awaitable[None]]

try:
    import openai
    from openai import OpenAI
except Exception:  # pragma: no cover
    openai = None
    OpenAI = None

try:
    from mcp import ClientSession
    from mcp.client.sse import sse_client
except Exception:  # pragma: no cover - only needed when BACKEND=distributed
    ClientSession = None
    sse_client = None

_READ_TOOLS = {"get_recent_alerts", "get_alert_details", "check_ip_reputation", "lookup_ip_geolocation"}
_WRITE_TOOLS = {"quarantine_host", "revoke_credential"}


def _agent_creds(agent: str) -> tuple[str, str]:
    if agent == "threat-intel":
        return settings.threat_intel_client_id, settings.threat_intel_secret
    if agent == "remediation":
        return settings.remediation_client_id, settings.remediation_secret
    if agent == "triage":
        return settings.triage_client_id, settings.triage_secret
    raise ValueError(f"no client credentials for agent {agent!r}")


async def get_keycloak_token(client_id: str, client_secret: str) -> str:
    """client_credentials grant against Keycloak; returns the access token."""
    url = f"{settings.keycloak_issuer.rstrip('/')}/protocol/openid-connect/token"
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            url, data={"grant_type": "client_credentials"}, auth=(client_id, client_secret)
        )
    if resp.status_code != 200:
        raise RuntimeError(f"Keycloak token fetch failed for {client_id}: HTTP {resp.status_code} {resp.text[:200]}")
    return resp.json()["access_token"]


def _is_denied(text: str) -> tuple[bool, str | None, str | None]:
    """Detect the MCP server's forbidden shape. Returns (denied, reason, required_scope)."""
    try:
        obj = json.loads(text)
    except Exception:
        low = (text or "").lower()
        if "forbidden" in low or "required scope" in low or "not in capability manifest" in low:
            return True, (text or "")[:200], None
        return False, None, None
    if isinstance(obj, dict) and obj.get("error") == "forbidden":
        reason = obj.get("reason") or obj.get("detail") or "forbidden"
        return True, reason, obj.get("required_scope")
    return False, None, None


def _display_scope(name: str, args: dict, required_from_deny: str | None) -> str | None:
    """The scope badge for the UI. Prefer the real required_scope from a deny."""
    if required_from_deny:
        return required_from_deny
    if name == "execute_db_query":
        return soc_tools.scope_for_sql(args.get("sql", ""))
    if name in _READ_TOOLS:
        return "mcp:read"
    if name in _WRITE_TOOLS:
        return "mcp:write"
    return None


def _mcp_to_openai(tool) -> dict:
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description or "",
            "parameters": tool.inputSchema or {"type": "object", "properties": {}},
        },
    }


def _llm_client(session_id: str):
    return OpenAI(api_key=settings.proxy_token, base_url=settings.proxy_base_url,
                  default_headers={"x-cai-metadata-session-id": session_id})


# ==========================================================================
# TOOL-USING AGENTS against the real MCP server
# ==========================================================================
async def run_tool_agent(agent: str, system_prompt: str, task: str, emit: Emit) -> dict:
    client_id, secret = _agent_creds(agent)
    sid = agents._session_id(agent)
    await emit("agent_started", {"agent": agent, "role": agents.AGENT_ROLE[agent], "session_id": sid})
    await emit("agent_input", {"agent": agent, "text": task})

    llm = _llm_client(sid)
    token = await get_keycloak_token(client_id, secret)
    headers = {"Authorization": f"Bearer {token}"}

    async with sse_client(settings.mcp_server_url, headers=headers) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as mcp:
            await mcp.initialize()
            mcp_tools = (await mcp.list_tools()).tools
            tool_index = {t.name for t in mcp_tools}
            tools = [_mcp_to_openai(t) for t in mcp_tools]

            messages = [{"role": "system", "content": system_prompt},
                        {"role": "user", "content": task}]

            for _ in range(agents.MAX_ITERATIONS):
                try:
                    resp = llm.chat.completions.create(model=settings.model, messages=messages, tools=tools)
                except openai.APIStatusError as exc:
                    detail = agents._parse_block(exc)
                    await emit("guardrail_blocked", {"agent": agent, **detail})
                    raise agents.GuardrailBlocked(agent, detail)

                msg = resp.choices[0].message
                assistant = {"role": "assistant", "content": msg.content}
                if msg.tool_calls:
                    assistant["tool_calls"] = [
                        {"id": tc.id, "type": "function",
                         "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                        for tc in msg.tool_calls
                    ]
                messages.append(assistant)

                if not msg.tool_calls:
                    parsed = agents._try_json(msg.content) or {"raw": msg.content}
                    await emit("agent_message", {"agent": agent, "kind": "result", "content": parsed})
                    await emit("agent_finished", {"agent": agent, "status": "ok"})
                    return parsed

                for tc in msg.tool_calls:
                    name = tc.function.name
                    try:
                        args = json.loads(tc.function.arguments or "{}")
                    except json.JSONDecodeError:
                        args = {}
                    if name not in tool_index:
                        text = json.dumps({"error": "forbidden",
                                           "reason": f"tool {name!r} not advertised by MCP"})
                    else:
                        try:
                            result = await mcp.call_tool(name, args)
                            text = "\n".join(getattr(b, "text", str(b)) for b in result.content)
                        except Exception as ex:
                            text = json.dumps({"error": "tool execution failed", "detail": str(ex)})

                    denied, reason, required = _is_denied(text)
                    await emit("tool_call", {"agent": agent, "tool": name, "args": args,
                                             "scope": _display_scope(name, args, required),
                                             "allowed": not denied, "denied_reason": reason,
                                             "result": text})
                    messages.append({"role": "tool", "tool_call_id": tc.id, "content": text})

            await emit("agent_finished", {"agent": agent, "status": "max_iterations"})
            return {"outcome": "partial", "summary": "reached max tool rounds"}


# ==========================================================================
# COMMS via real A2A to the Comms container
# ==========================================================================
async def run_comms(skill: str, payload: dict, caller: str, emit: Emit) -> dict:
    sid = agents._session_id("comms")
    await emit("agent_started", {"agent": "comms", "role": agents.AGENT_ROLE["comms"], "session_id": sid})
    await emit("agent_input", {"agent": "comms", "text": f"{skill} <- {caller}: {json.dumps(payload)[:160]}"})

    # The A2A caller identity is the Triage agent's OAuth client.
    cid, secret = settings.triage_client_id, settings.triage_secret
    try:
        token = await get_keycloak_token(cid, secret)
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
        await emit("agent_message", {"agent": "comms", "kind": "notify", "content": result})
        await emit("agent_finished", {"agent": "comms", "status": "error"})
        return result

    url = f"{settings.comms_a2a_url.rstrip('/')}/a2a/skills/{skill}"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload, headers={"Authorization": f"Bearer {token}"})
    except Exception as ex:
        result = {"ok": False, "error": f"A2A call failed: {ex}"}
        await emit("tool_call", {"agent": "comms", "tool": f"a2a:{skill}", "args": payload,
                                 "scope": "a2a-card", "allowed": False, "denied_reason": str(ex),
                                 "result": json.dumps(result)})
        await emit("agent_message", {"agent": "comms", "kind": "notify", "content": result})
        await emit("agent_finished", {"agent": "comms", "status": "error"})
        return result

    try:
        body = resp.json()
    except Exception:
        body = {"raw": resp.text[:300]}
    allowed = resp.status_code == 200 and body.get("ok", True) is not False
    reason = None if allowed else (body.get("reason") or body.get("error") or f"HTTP {resp.status_code}")

    await emit("tool_call", {"agent": "comms", "tool": f"a2a:{skill}", "args": payload,
                             "scope": "a2a-card", "allowed": allowed, "denied_reason": reason,
                             "result": json.dumps(body, indent=2)})
    await emit("agent_message", {"agent": "comms", "kind": "notify", "content": body})
    await emit("agent_finished", {"agent": "comms", "status": "ok" if allowed else "denied"})
    return body
