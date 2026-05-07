@echo off
title WebSentinel - BitB Detection Test
cd /d "E:\Sliit\2023\Year 4\Sem1\Research\New Research\Code\t06-security-browser"
set PYTHONUTF8=1
set PYTHONPATH=E:\Sliit\2023\Year 4\Sem1\Research\New Research\Code\t06-security-browser

echo ============================================
echo  WebSentinel - BitB Detection Test
echo ============================================
echo  Make sure run.bat is already running first!
echo ============================================
echo.
C:\Python312\python.exe -u tests\test_bitb_detection.py

echo.
pause
