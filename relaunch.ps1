$ErrorActionPreference = 'Stop'
$appRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$electronExe = Join-Path $appRoot "electron\node_modules\electron\dist\electron.exe"
$electronApp = Join-Path $appRoot "electron"

# Kill any existing Electron and Python/uvicorn instances
Get-Process -Name electron -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process -Name python   -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 600

# Clear ELECTRON_RUN_AS_NODE (set by VSCode, prevents browser process init)
[System.Environment]::SetEnvironmentVariable('ELECTRON_RUN_AS_NODE', $null, 'Process')
Remove-Item Env:ELECTRON_RUN_AS_NODE -ErrorAction SilentlyContinue

Write-Host "Launching WebSentinel..." -ForegroundColor Green
Write-Host "App: $electronApp"

$proc = Start-Process -FilePath $electronExe -ArgumentList "`"$electronApp`"" -PassThru
Write-Host "PID: $($proc.Id)"
Start-Sleep 3
$count = (Get-Process -Name electron -ErrorAction SilentlyContinue | Measure-Object).Count
Write-Host "Electron processes running: $count"
