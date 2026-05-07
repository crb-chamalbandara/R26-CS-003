@echo off
title WebSentinel - Logo Hash Generator (L3)
cd /d "E:\Sliit\2023\Year 4\Sem1\Research\New Research\Code\t06-security-browser"
set PYTHONUTF8=1
set PYTHONPATH=E:\Sliit\2023\Year 4\Sem1\Research\New Research\Code\t06-security-browser

echo ============================================
echo  Installing required packages...
echo ============================================
C:\Python312\python.exe -m pip install imagehash Pillow httpx --quiet

echo.
echo ============================================
echo  WebSentinel - Generating Brand Logo Hashes
echo ============================================
echo.
C:\Python312\python.exe -u scripts\generate_logo_hashes.py

echo.
echo ============================================
echo  Done! Press any key to close.
echo ============================================
pause
