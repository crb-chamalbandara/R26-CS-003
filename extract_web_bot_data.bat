@echo off
echo ================================================================
echo   C3 -- Extract web_bot_detection_dataset into c3_web_bot_sessions.csv
echo ================================================================
echo.
python scripts\extract_web_bot_sessions.py
echo.
pause
