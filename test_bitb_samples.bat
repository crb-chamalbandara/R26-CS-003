@echo off
title WebSentinel - BITB Samples Test
cd /d "E:\Sliit\2023\Year 4\Sem1\Research\New Research\Code\t06-security-browser"
set PYTHONUTF8=1
set PYTHONPATH=E:\Sliit\2023\Year 4\Sem1\Research\New Research\Code\t06-security-browser

echo ============================================
echo  WebSentinel - mrd0x/BITB Detection Test
echo  (run.bat must be running first!)
echo ============================================
echo.

C:\Python312\python.exe -u tests\test_bitb_samples.py

echo.
pause
