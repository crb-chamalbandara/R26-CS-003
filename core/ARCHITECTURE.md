# Core — Shared Infrastructure

## Purpose
`core/` is the backbone of WebSentinel. It owns:
- The **FastAPI API gateway** that routes requests to each component
- The **Playwright session manager** (persistent Chromium browser shared by all components)
- The **WebSocket broadcast layer** for real-time dashboard updates

All component modules (`c1/`, `c2/`, `c3/`, `c4/`) are imported here and exposed via REST/WebSocket.

---

## Tech Stack
| Layer | Technology |
|-------|-----------|
| Web framework | FastAPI + Uvicorn (async) |
| Browser automation | Playwright (`launch_persistent_context`) |
| Real-time comms | WebSocket (FastAPI native) |
| Data validation | Pydantic v2 |

---

## File Map

| File | Role |
|------|------|
| `main.py` | FastAPI app — all HTTP + WebSocket endpoints |
| `playwright_session.py` | Singleton headful Chromium session, nav callbacks |
| `__init__.py` | Package marker |

---

## Key Patterns

### Component Integration
Each component exposes one or more async functions that `core/main.py` calls:

```python
# Signature contract every component must satisfy
async def check_*(url, ...) -> dict:
    return {"score": float,   # 0.0 – 1.0
            "detail": str}    # human-readable explanation
```

### Launching the backend
```bash
# From project root (WebSentinel/)
python -m uvicorn core.main:app --host 127.0.0.1 --port 8000 --reload
```

### Adding a new component endpoint
1. Implement `async def check_*(...)` in the component's module
2. Import it in `core/main.py`
3. Add a `layer_jobs.append(...)` entry in `analyze()`
4. Adjust the `weights` dict if needed (must sum to 1.0)

### WebSocket event types
| Type | Payload | Description |
|------|---------|-------------|
| `init` | `{session_running, url}` | Sent on WS connect |
| `analysis` | `{url, verdict, risk_score, layers, timestamp}` | Full analysis result |
| `url_change` | `{url, title}` | Navigation event |
| `session_started` | `{url}` | Playwright browser ready |
| `session_stopped` | `{}` | Browser closed |
| `session_error` | `{message}` | Start failure |

---

## Implementation Status
- ✅ FastAPI gateway with /health, /analyze, /alerts, /settings
- ✅ Playwright persistent session (cookies/logins survive restarts)
- ✅ WebSocket real-time broadcast
- ✅ Session start/stop/navigate endpoints

---

## AI Session Starter
> Paste this into a new AI chat to get instant context:
>
> "I'm working on WebSentinel, a browser security research platform. The `core/` folder
> contains the FastAPI gateway (`core/main.py`) and Playwright session manager
> (`core/playwright_session.py`). The backend runs from the project root with
> `python -m uvicorn core.main:app`. Components c1-c4 each export async `check_*`
> functions returning `{score: float, detail: str}`. I need help with: [YOUR TASK]"
