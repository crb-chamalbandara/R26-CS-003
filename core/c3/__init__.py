# Component 3 — Browser Execution Aware C2 Beacon Detector

# This package contains all the pieces that make up C3.
# C3 sits inside the running WebSentinel browser and watches every network
# request the browser makes.  It asks one question: "Is this traffic from a
# human browsing normally, or from a hidden program that phones home on a
# clockwork schedule?"
#
# The sub-modules work as a pipeline, in this order:
#
#   interceptor.py      — hooks into the browser and captures every outgoing
#                         request (URL, method, size, timing)
#
#   context_tagger.py   — for each captured request, records whether the user
#                         was active (clicked / typed), whether the tab was
#                         in the background, and how long the user had been idle
#
#   feature_engine.py   — turns the list of requests for each destination host
#                         into 29 numbers (features) that describe the traffic
#                         pattern (timing regularity, request rate, same-site
#                         alignment, script-vs-parser initiator, etc.)
#
#   anomaly_engine.py   — an isotonic-calibrated XGBoost model scores 18 of
#                         those features for bot-like HTTP behaviour
#
#   heuristic rules     — simple if/then rules inside analyzer.py that look for
#                         patterns like "very regular timing + user is idle"
#
#   risk_fusion.py      — combines the ML scores and heuristic score into one
#                         final number (0–1) and decides SAFE / SUSPICIOUS / BEACON
#
#   reputation_engine.py — once a BEACON is confirmed, checks the destination
#                          against threat-intelligence databases (AbuseIPDB,
#                          VirusTotal) and shows the result as analyst evidence
#                          (it is not folded into the risk score)
#
#   alert_store.py      — saves confirmed BEACON alerts to a local SQLite database
#                         so they survive restarts and can be shown in the dashboard
#
#   analyzer.py         — the main loop that runs every 10 seconds, feeds each
#                         host's request window through the pipeline above, and
#                         triggers alerts when the verdict is BEACON
