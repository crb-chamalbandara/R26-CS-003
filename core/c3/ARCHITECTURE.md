# Component 3 — C2 Beacon: Browser Execution Aware C2 Beacon Detector

> **Status:** 🔲 Not yet implemented — contributor welcome

## Research Question
Can runtime context-aware network monitoring inside the browser detect C2 beaconing
behaviour from malicious extensions, even when the traffic uses legitimate platforms
(Google Docs, Discord, GitHub)?

---

## Architecture Overview

```
Browser Network Events (via CDP / Playwright route interception)
      │
      ├── Tab ID, Extension ID, User-active flag
      ├── Request URL, method, headers, payload size
      └── Timing (inter-request intervals)
              │
              ▼
        Feature vector per request sequence
              │
              ▼
      ML Beaconing Classifier
      (periodic timing patterns, encoded payloads, covert channels)
              │
              ▼
    Block + Flag → Responsible extension quarantined
```

---

## Tech Stack
| Layer | Recommended Technology |
|-------|----------------------|
| Network interception | Playwright `route()` or Chrome DevTools Protocol (CDP) |
| Context tagging | CDP `Network.enable` + `Target.getTargetInfo` |
| ML model | Isolation Forest / LSTM on request timing sequences |
| Storage | SQLite (in-process, zero-config) |

---

## File Map

| File | Role |
|------|------|
| `__init__.py` | Package marker |
| `interceptor.py` | **(create)** CDP/Playwright network hook — logs all outbound requests |
| `context_tagger.py` | **(create)** Attaches tab/extension/user-active context to each request |
| `beacon_model.py` | **(create)** ML beaconing classifier |
| `blocker.py` | **(create)** Request blocking + extension flagging |
| `models/` | **(create)** Trained model files |

---

## Integration Interface
`core/main.py` will call (once implemented):

```python
from c3.interceptor import start_interception, get_recent_requests
from c3.beacon_model import classify_beaconing

# Result: {"score": float, "detail": str, "blocked_requests": list}
```

A new endpoint `/c3/beacon/status` should be added to `core/main.py`.

---

## Implementation TODO
- [ ] Hook CDP `Network` domain via Playwright's `expose_binding` or direct CDP
- [ ] Tag each request with tab ID, extension origin, user-activity flag
- [ ] Build labeled dataset of beacon vs. legitimate traffic
- [ ] Train timing-based ML model (Isolation Forest recommended for anomaly detection)
- [ ] Implement request blocking via Playwright `route.abort()`
- [ ] Add `/c3/beacon/status` endpoint to `core/main.py`
- [ ] Add C3 live panel to frontend dashboard

---

## AI Session Starter
> Paste this into a new AI chat to get instant context:
>
> "I'm building Component 3 of WebSentinel — a Browser Execution Aware C2 Beacon Detector.
> Project root: `WebSentinel/`. Shared infra in `core/` (FastAPI + Playwright session at
> `core/playwright_session.py`). My component code goes in `c3/`. The goal is to intercept
> all outbound browser network requests via Playwright's route API or CDP, tag each with
> tab/extension/user-activity context, then apply ML to detect beaconing patterns. I need
> help with: [YOUR TASK]"
