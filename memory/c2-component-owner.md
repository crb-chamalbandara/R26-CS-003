---
name: c2-component-owner
description: User owns Component 2 (C2) of WebSentinel — the BitB phishing detector
metadata:
  type: project
---

User's component in WebSentinel (R26-CS-003) is **C2 = Component 2 = the Browser-in-the-Browser
(BitB) phishing detector** in `core/c2/` (layers 1–5). NOT command-and-control — that naming
collision is a trap; the C2-beacon detector is actually component **C3**.

Active work: the BitB test suite under `test/C2/` (graded anomaly pages 50/75/100, mrd0x BiTB
kit samples, `test_bitb_*.py`). Per-component GitHub branches (origin/C1..C4) are currently
just snapshots equal to main. See [[git-push-auth]].
