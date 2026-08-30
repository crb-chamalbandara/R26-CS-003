@echo off
title WebSentinel - Test Page Server
cd /d "E:\Sliit\2023\Year 4\Sem1\Research\New Research\GithubMerge\repo\test\C2"
set PYTHONUTF8=1

echo ============================================
echo  WebSentinel - Test Page Server (port 8080)
echo ============================================
echo.
echo  Navigate to one of these in WebSentinel browser:
echo.
echo  [Your custom test page]
echo    http://127.0.0.1:8080/bitb_test.html
echo.
echo  [mrd0x BITB Templates - Windows Chrome Light]
echo    http://127.0.0.1:8080/bitb_samples/Windows-Chrome-LightMode/index.html
echo.
echo  [mrd0x BITB Templates - Windows Chrome Dark]
echo    http://127.0.0.1:8080/bitb_samples/Windows-Chrome-DarkMode/index.html
echo.
echo  [mrd0x BITB Templates - MacOS Chrome Light]
echo    http://127.0.0.1:8080/bitb_samples/MacOS-Chrome-LightMode/index.html
echo.
echo  [mrd0x BITB Templates - MacOS Chrome Dark]
echo    http://127.0.0.1:8080/bitb_samples/MacOS-Chrome-DarkMode/index.html
echo.
echo  [mrd0x BITB Templates - Windows Dark with Delay]
echo    http://127.0.0.1:8080/bitb_samples/Windows-DarkMode-Delay/index.html
echo.
echo  -- Anomaly Score Test Pages (C2 Layer 1 targets) --
echo  [L1 Anomaly 50%% - Google theme - Rules R2+R5 only]
echo    http://127.0.0.1:8080/bitb_anomaly_50.html
echo.
echo  [L1 Anomaly 75%% - Google theme - Rules R1+R2+R4 only]
echo    http://127.0.0.1:8080/bitb_anomaly_75.html
echo.
echo  [L1 Anomaly 100%% - PayPal theme - All 5 rules]
echo    http://127.0.0.1:8080/bitb_anomaly_100.html
echo.
echo  Keep this window open. Press Ctrl+C to stop.
echo ============================================
echo.

C:\Python312\python.exe -m http.server 8080

pause
