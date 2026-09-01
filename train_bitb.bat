@echo off
title BitB HTML Classifier Training
cd /d "E:\Sliit\2023\Year 4\Sem1\Research\New Research\Code\t06-security-browser"
set PYTHONUTF8=1
set PYTHONPATH=E:\Sliit\2023\Year 4\Sem1\Research\New Research\Code\t06-security-browser
echo ============================================
echo  WebSentinel - BitB HTML Classifier Training
echo ============================================
echo.
C:\Python312\python.exe -u scripts\prepare_html_dataset.py
echo.
echo ============================================
echo  Training complete! Press any key to close.
echo ============================================
pause
