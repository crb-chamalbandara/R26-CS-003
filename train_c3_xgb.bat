@echo off
echo ================================================================
echo   C3 -- Train XGBoost classifier  (CTU-13 + IoT-23 C2, production)
echo ================================================================
echo.
echo Requires: data\c3_xgb_training.csv
echo Trains on real CTU-13 + IoT-23 C2-channel traffic (label_c2), 7
echo network-flow features. Overwrites models\c3_xgb_classifier.pkl --
echo the file C3 actually loads. Restart the WebSentinel backend after.
echo.
echo NOTE: this model is calibrated for the 0.52 BEACON threshold in
echo core\c3\risk_fusion.py. The two belong together -- see
echo C3_FullPipeline_XGB_Results.md before changing either.
echo.
python scripts\train_c3_xgb_production.py
echo.
pause
