@echo off
title C3 Beacon Detector Training
cd /d "%~dp0"
set PYTHONUTF8=1
set PYTHONPATH=%~dp0
.venv\Scripts\python.exe -u -m scripts.train_c3_model
pause
