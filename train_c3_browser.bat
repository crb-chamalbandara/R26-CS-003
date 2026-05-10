@echo off
title C3 Browser Context Model Training
cd /d "%~dp0"
set PYTHONUTF8=1
set PYTHONPATH=%~dp0
.venv\Scripts\python.exe -u -m scripts.train_c3_browser_model
pause
