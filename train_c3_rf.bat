@echo off
echo ================================================================
echo   C3 -- Train Random Forest classifier  (HTTP behavior, Model 2)
echo ================================================================
echo.
echo Requires: data\c3_web_bot_sessions.csv
echo Run extract_web_bot_data.bat first if that file does not exist.
echo.
python scripts\train_c3_rf_model.py
echo.
pause
