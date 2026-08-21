"""HTTP+SSE shim that makes a batch agent callable, WITHOUT touching agent.py.

It imports the local ``agent`` module and reuses its exact system prompt,
CalypsoAI config, and helpers, then runs the same loop the agent runs on the
CLI — but streams structured events over SSE instead of printing. This lets the
soc-mas orchestrator fire a task at the real agent container and get back real
per-tool results and real denials for the UI.

Two modes (set AGENT_KIND):
  * planner  (triage)      -> one proxy call, returns the JSON plan. No tools.
  * tool     (threat-intel/remediation) -> the agentic MCP loop: real Keycloak
                              token, real MCP SSE session, real tool calls.

Endpoints:
  GET  /health  -> liveness
  POST /run     -> SSE stream. Body {"alert": "..."} (planner) or {"task": "..."} (tool)
"""

from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

import agent  # the unmodified agent.py in this image

try:
    import openai as openai_mod
    from openai import OpenAI
except Exception:  # pragma: no cover
    openai_mod = None
    OpenAI = None

try:
    from mcp import ClientSession
    from mcp.client.sse import sse_client
except Exception:  # pragma: no cover - only needed in tool mode
    ClientSession = None
    sse_client = None

AGENT_KIND = os.environ.get("AGENT_KIND", "tool").lower()
AGENT_NAME = os.environ.get("AGENT_NAME", getattr(agent, "AGENT_NAME", "agent"))
MODEL = getattr(agent, "CALYPSOAI_MODEL", os.environ.get("CALYPSOAI_MODEL", "gpt-4o-mini"))
MAX_ITERATIONS = int(os.environ.get("MAX_ITERATIONS", getattr(agent, "MAX_ITERATIONS", 8)))

app = FastAPI(title=f"{AGENT_NAME} shim")


def _sse(payload: dict) -> bytes:
    return f"data: {json.dumps(payload, default=str)}\n\n".encode("utf-8")


def _session_id() -> str:
    return "-".join([uuid.uuid4().hex[:8], AGENT_NAME,
                     datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"), uuid.uuid4().hex[:6]])


def _client(session_id: str):
    return OpenAI(api_key=agent.CALYPSOAI_TOKEN, base_url=agent.CALYPSOAI_OPENAI_API_BASE,
                  default_headers={"x-cai-metadata-session-id": session_id})


def _try_json(text: str):
    s = (text or "").strip()
    s = re.sub(r"^```(?:json)?\s*", "", s)
    s = re.sub(r"\s*```\s*$", "", s)
    try:
        return json.loads(s)
    except Exception:
        return None


def _parse_block(exc) -> dict:
    try:
        body = exc.response.json()
    except Exception:
        return {"status": getattr(exc, "status_code", "?")}
    cai = ((body.get("error") or {}).get("cai_error") or {})
    failing = [r.get("scanner_id") for r in (cai.get("scanner_results") or []) if r.get("outcome") == "failed"]
    return {"status": getattr(exc, "status_code", "?"), "outcome": cai.get("outcome"),
            "failing_scanners": failing, "body": body}


# --- scope label for the UI badge (mirrors the MCP server's scope_for_sql) ---
_READ = {"get_recent_alerts", "get_alert_details", "check_ip_reputation", "lookup_ip_geolocation"}
_WRITE = {"quarantine_host", "revoke_credential"}


def _scope_for_sql(sql: str) -> str:
    s = (sql or "").strip().lstrip("(").lstrip()
    parts = s.split(None, 1)
    verb = parts[0].upper() if parts else ""
    upper = s.upper()
    if verb == "SELECT":
        return "mcp:read"
    if verb == "DELETE":
        return "mcp:write" if " WHERE " in upper else "mcp:admin"
    if verb in ("INSERT", "UPDATE"):
        return "mcp:write"
    if verb in ("DROP", "CREATE", "ALTER", "TRUNCATE", "GRANT", "REVOKE"):
        return "mcp:admin"
    return "mcp:admin"


def _display_scope(name: str, args: dict, required: str | None) -> str | None:
    if required:
        return required
    if name == "execute_db_query":
        return _scope_for_sql(args.get("sql", ""))
    if name in _READ:
        return "mcp:read"
    if name in _WRITE:
        return "mcp:write"
    return None


def _is_denied(text: str):
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


# ==========================================================================
# planner (triage)
# ==========================================================================
async def _planner_stream(alert: str):
    sid = _session_id()
    yield _sse({"type": "started", "session_id": sid})
    try:
        client = _client(sid)
        try:
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[{"role": "system", "content": agent.SYSTEM_PROMPT},
                          {"role": "user", "content": alert}],
            )
        except openai_mod.APIStatusError as exc:
            yield _sse({"type": "guardrail_blocked", **_parse_block(exc)})
            return
        content = resp.choices[0].message.content or ""
        plan = _try_json(content) or {"summary": alert[:120], "severity": "medium", "tasks": []}
        yield _sse({"type": "message", "content": plan})
    except Exception as exc:  # noqa: BLE001
        yield _sse({"type": "error", "message": f"{type(exc).__name__}: {exc}"})


# ==========================================================================
# tool agent (threat-intel / remediation) — the real MCP loop
# ==========================================================================
async def _tool_stream(task: str):
    sid = _session_id()
    yield _sse({"type": "started", "session_id": sid})
    try:
        client = _client(sid)
        token = await agent.fetch_oauth_token()
        headers = {"Authorization": f"Bearer {token}"} if token else None

        async with sse_client(agent.MCP_SERVER_URL, headers=headers) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as mcp:
                await mcp.initialize()
                mcp_tools = (await mcp.list_tools()).tools
                names = {t.name for t in mcp_tools}
                tools = [agent.mcp_tool_to_openai_function(t) for t in mcp_tools]

                messages = [{"role": "system", "content": agent.SYSTEM_PROMPT},
                            {"role": "user", "content": task}]

                for _ in range(MAX_ITERATIONS):
                    try:
                        resp = client.chat.completions.create(model=MODEL, messages=messages, tools=tools)
                    except openai_mod.APIStatusError as exc:
                        yield _sse({"type": "guardrail_blocked", **_parse_block(exc)})
                        return

                    msg = resp.choices[0].message
                    messages.append(agent.assistant_message(msg))

                    if not msg.tool_calls:
                        yield _sse({"type": "message", "content": _try_json(msg.content) or {"raw": msg.content}})
                        return

                    for tc in msg.tool_calls:
                        name = tc.function.name
                        try:
                            args = json.loads(tc.function.arguments or "{}")
                        except json.JSONDecodeError:
                            args = {}
                        if name not in names:
                            text = json.dumps({"error": "forbidden", "reason": f"tool {name!r} not advertised by MCP"})
                        else:
                            try:
                                result = await mcp.call_tool(name, args)
                                text = "\n".join(getattr(b, "text", str(b)) for b in result.content)
                            except Exception as ex:
                                text = json.dumps({"error": "tool execution failed", "detail": str(ex)})

                        denied, reason, required = _is_denied(text)
                        yield _sse({"type": "tool_call", "tool": name, "args": args,
                                    "scope": _display_scope(name, args, required),
                                    "allowed": not denied, "denied_reason": reason, "result": text})
                        messages.append({"role": "tool", "tool_call_id": tc.id, "content": text})

                yield _sse({"type": "message", "content": {"outcome": "partial", "summary": "reached max tool rounds"}})
    except Exception as exc:  # noqa: BLE001
        yield _sse({"type": "error", "message": f"{type(exc).__name__}: {exc}"})


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({"status": "ok", "agent": AGENT_NAME, "kind": AGENT_KIND})


@app.post("/run")
async def run(request: Request) -> StreamingResponse:
    body = await request.json()
    if AGENT_KIND == "planner":
        alert = body.get("alert") or body.get("task") or ""
        gen = _planner_stream(alert)
    else:
        task = body.get("task") or body.get("alert") or ""
        gen = _tool_stream(task)
    return StreamingResponse(gen, media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
