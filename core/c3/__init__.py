# Component 3 -- Browser Execution Aware C2 Beacon Detector
#
# C3 runs inside the WebSentinel browser and watches every request the browser
# makes. It asks one question per destination host: is this a person browsing,
# or a hidden program phoning home on a clockwork schedule?
#
# The modules form a pipeline, in this order:
#
#   interceptor.py       captures every outgoing request through the Chrome
#                        DevTools Protocol (URL, method, size, timing) without
#                        pausing the browser, and keeps a rolling window of the
#                        last 50 requests per host
#
#   context_tagger.py    records, for each request, whether the user was active
#                        (clicked or typed), whether the tab was in the
#                        background, and how long the user had been idle
#
#   feature_engine.py    turns one host's window into 32 numbers describing the
#                        traffic pattern: timing regularity, request rate,
#                        same-site alignment, script or parser initiator, and
#                        so on
#
#   ml_classifier.py     an XGBoost model scores 20 of those 32 features and
#                        reports how much the window looks like a C2 beacon
#
#   analyzer.py          the 10-second loop. Holds the heuristic rules (the
#                        second, independent signal), applies every gate
#                        between a score and an alert, and drives the rest of
#                        the pipeline
#
#   risk_fusion.py       combines the ML and heuristic scores into one number
#                        from 0 to 1 and decides SAFE, SUSPICIOUS or BEACON
#
#   reputation_engine.py after a BEACON is confirmed, looks the destination up
#                        in AbuseIPDB and VirusTotal. This is analyst evidence
#                        only and is never folded into the risk score
#
#   alert_store.py       saves confirmed alerts to SQLite so they survive a
#                        restart and can be shown in the dashboard
#
#   block_store.py       persists a confirmed block with a 24-hour expiry, so a
#                        block survives a restart and lifts itself on time
#
# Documentation lives in researches/C3/: ARCHITECTURE.md for how the whole
# component fits together, C3_Final_Model_Results.md for the model's
# engineering record, and C3_Training_Dataset_Feature_Dictionary.md for the
# training data. C3_ML_Train.ipynb in this folder retrains the deployed model
# from data/c3_training_dataset_clear.csv and recomputes every result it shows.
#
# ARCHIVED PATHS IN COMMENTS. Comments throughout this package cite training
# scripts, evaluation scripts, result JSON files and standalone test cases that
# the running app does not need. Those were moved out of the repository, not
# deleted, and are under:
#
#     Desktop\Removals in C3\L A S T - Removals\
#
# at the same relative paths (2026-09-15_runtime_only_clean\ for the code and
# data, 2026-09-17_c3_cleanup\ for the earlier working notes). So a comment
# citing scripts/train_c3_final_model.py means that file, in the archive.
