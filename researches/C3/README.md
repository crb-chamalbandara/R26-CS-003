# C3 research documents

C3 is WebSentinel's Browser Execution Aware C2 Beacon Detector. Its code is in
`core/c3/`, its model is `models/c3_beacon_classifier.pkl`, and the model's
notebook is `core/c3/C3_ML_Train.ipynb`, which retrains the model from
`data/c3_training_dataset_clear.csv` and recomputes every result.

| File | What it is |
|---|---|
| `ARCHITECTURE.md` | How C3 works: pipeline, modules, features, model, heuristic rules, fusion, gates, dashboard, tests, limitations |
| `C3_Final_Model_Results.md` | The deployed model's full engineering record: data corrections, every measured design choice, results |
| `C3_Training_Dataset_Feature_Dictionary.md` | Every column of `data/c3_training_dataset_clear.csv` |
| `TEST_CASE_01_Cobalt_Strike_Beacon_via_Compromised_WordPress.md` | Test case 01: live beacon from a page the user left open |
| `TEST_CASE_02_Discord_Cloud_APT_Dual_Channel_Beacon.md` | Test case 02: beacon in a second tab while the user browses |
| `TEST_CASE_03_Real_World_Reputation_Checked_C2_Beacon.md` | Test case 03: a real beacon over a public ngrok tunnel, with a live threat-intel lookup |
| `C3_FULL_EXPLAIN.txt` | Full technical reference, file by file |
| `ML_EXPLAIN.txt` | Deep analysis of the model for a research or viva panel |
| `papers/` | The ten research papers behind C3's design, with an index saying what each one contributes |

Everything in this folder describes the C3 that is running now. The numbers come
from the deployed model and the dataset it was trained on, and the notebook
recomputes them from those two files, so nothing here is typed in by hand.

## Where the older notes went

Four dated working files (`Final_Publish_Plan.txt`, `Publish_C3.txt`,
`Publish_ML.txt`, `Publish_ML_improve.txt`) described earlier versions of C3
and disagreed with the code in places. They were moved on 2026-09-17, not
deleted, to:

    Desktop\Removals in C3\L A S T - Removals\2026-09-17_c3_cleanup\researches_C3_working_notes\

The two that were still accurate were kept and updated: `C3_FULL_EXPLAIN.txt`
(formerly `Claude_Chat.txt`) and `ML_EXPLAIN.txt` (formerly `ML-Explain.txt`).
The superseded notebooks (`ML_Publish.ipynb`, `01_xgboost_model.ipynb`) and the
model file under its old name are in
`L A S T - Removals\2026-09-17_c3_final\`.

The change record they carried (the 2026-09-11 hardening pass, steps 1 to 8) is
summarised in `ARCHITECTURE.md`, and the code comments that used to cite the
plan file now name the step directly.
