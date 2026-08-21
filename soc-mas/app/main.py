"""FastAPI entrypoint -- structure modeled on the MAS demo's app/main.py.

Endpoints:
  GET  /                       -> the single-page UI
  GET  /health                 -> liveness + whether we're in mock mode
  GET  /api/scenarios          -> canned scenario list for the picker
  POST /api/run/stream         -> Server-Sent Events for one run (the live flow)
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .config import settings
from .workflow import SocWorkflow

app = FastAPI(title=settings.app_name, version="0.1.0")
_ui = Path(__file__).resolve().parent / "ui"
app.mount("/ui-static", StaticFiles(directory=_ui / "static"), name="ui-static")
_workflow = SocWorkflow()


class RunRequest(BaseModel):
    alert: str
    scenario_id: str | None = None


def _sse(payload: dict[str, Any]) -> bytes:
    # Single default-event stream; the event kind travels inside the JSON.
    return f"data: {json.dumps(payload, default=str)}\n\n".encode("utf-8")


@app.get("/", include_in_schema=False)
async def root() -> FileResponse:
    return FileResponse(_ui / "index.html")


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "backend": settings.backend, "mock_mode": settings.mock_mode, "model": settings.model}


@app.get("/api/scenarios")
async def api_scenarios() -> list[dict]:
    return _workflow.list_scenarios()


@app.post("/api/run/stream")
async def run_stream(req: RunRequest) -> StreamingResponse:
    queue: asyncio.Queue[dict | None] = asyncio.Queue()

    async def emit(event: str, payload: dict[str, Any]) -> None:
        await queue.put({"type": event, **payload})

    async def worker() -> None:
        try:
            await _workflow.run(req.alert, emit, scenario_id=req.scenario_id)
        except Exception as exc:  # noqa: BLE001
            await queue.put({"type": "error", "message": str(exc)})
        finally:
            await queue.put(None)

    async def stream():
        task = asyncio.create_task(worker())
        # tell the client up front whether this is a live or mock run
        yield _sse({"type": "hello", "backend": settings.backend, "mock_mode": settings.mock_mode, "model": settings.model})
        try:
            while True:
                item = await queue.get()
                if item is None:
                    break
                yield _sse(item)
        finally:
            if not task.done():
                task.cancel()

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
