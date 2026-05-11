"""
C3 risk fusion.

Combines anomaly, reputation, and heuristic scores with adaptive weights.
"""
from __future__ import annotations


class C3RiskFusion:
    def fuse(
        self,
        anomaly: float | None,
        reputation: float | None,
        heuristic: float | None,
        browser_anomaly: float | None = None,
    ) -> dict:
        heuristic_value = float(heuristic or 0.0)
        has_anomaly    = anomaly is not None
        has_reputation = reputation is not None
        has_browser    = browser_anomaly is not None

        if has_anomaly and has_reputation and has_browser:
            weights = {"anomaly": 0.40, "browser_anomaly": 0.20, "reputation": 0.25, "heuristic": 0.15}
        elif has_anomaly and has_reputation:
            weights = {"anomaly": 0.55, "reputation": 0.25, "heuristic": 0.20}
        elif has_anomaly and has_browser and not has_reputation:
            weights = {"anomaly": 0.45, "browser_anomaly": 0.20, "heuristic": 0.35}
        elif has_reputation and not has_anomaly:
            weights = {"heuristic": 0.55, "reputation": 0.45}
        elif has_anomaly and not has_reputation:
            weights = {"anomaly": 0.65, "heuristic": 0.35}
        else:
            weights = {"heuristic": 1.0}

        score = 0.0
        if has_anomaly:
            score += float(anomaly) * weights.get("anomaly", 0.0)
        if has_browser:
            score += float(browser_anomaly) * weights.get("browser_anomaly", 0.0)
        if has_reputation:
            score += float(reputation) * weights.get("reputation", 0.0)
        score += heuristic_value * weights.get("heuristic", 0.0)

        overrides = []
        if has_reputation and float(reputation) >= 0.8:
            score = max(score, 0.60)
            overrides.append("reputation override")
        if has_anomaly and float(anomaly) >= 0.80 and heuristic_value >= 0.50:
            score = max(score, 0.60)
            overrides.append("anomaly+heuristic override")

        # Safety guard: do NOT reach BEACON on anomaly signal alone (no reputation, no heuristic).
        # The IF model has ~9% false positive rate on pcap data; heuristic confirmation is required.
        if score >= 0.6 and not has_reputation and heuristic_value < 0.10:
            score = min(score, 0.59)
            overrides.append("anomaly-only cap: awaiting heuristic confirmation")

        score = max(0.0, min(1.0, float(score)))
        verdict = "BEACON" if score >= 0.6 else "SUSPICIOUS" if score >= 0.3 else "SAFE"
        detail = "Fusion weights " + ", ".join(f"{k}={v:.2f}" for k, v in weights.items())
        if overrides:
            detail += "; " + ", ".join(overrides)

        return {
            "score": round(score, 4),
            "verdict": verdict,
            "detail": detail,
            "weights": weights,
        }


c3_risk_fusion = C3RiskFusion()
