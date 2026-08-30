---
name: c2-component-owner
description: User owns Component 2 (C2) of WebSentinel — the BitB phishing detector
metadata:
  type: project
---

User's component in WebSentinel (R26-CS-003) is **C2 = Component 2 = the Browser-in-the-Browser
(BitB) phishing detector** in `core/c2/` — now **6 layers** (L6 runtime behavioural) plus a
verified-domain trust gate and a configurable weighted-sum fusion with a decisive-signal floor.
NOT command-and-control — that naming collision is a trap; the C2-beacon detector is actually
component **C3**.

Active work: C2 tests under `test/C2/` — offline suites (`test_c2_layers`, `test_layer6_runtime`,
`test_verified_domains`), realistic page fixtures in `test/C2/pages/` (built by `build_pages.py`
from the real mrd0x kits), and the dashboard Test-panel cases (`_tc_c2_*` in `core/main.py`,
served via SSE `/dev/run_tests_stream` — C2 14/14 live). `test_bitb_anomaly_levels.py`'s graded
50/75/100 expectations are stale (all anomaly pages now score ~1.00). Per-component GitHub
branches (origin/C1..C4) are currently just snapshots equal to main. See [[git-push-auth]].
