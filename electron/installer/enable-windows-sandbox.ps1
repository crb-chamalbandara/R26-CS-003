<#
.SYNOPSIS
  Turns on the Windows Sandbox feature for the WebSentinel Extension Analyzer (C1), only when it is needed.

.DESCRIPTION
  The installer runs this when the user ticks "Turn on Windows Sandbox". It can also be run by hand.

  It changes nothing when Windows Sandbox is already on, so running it twice, or on a PC that
  already has the feature, is harmless. The order is always:

    1. Is the launcher there?  (System32\WindowsSandbox.exe, the same test the app uses.)  Done.
    2. Not an administrator?   Ask Windows for administrator approval and run again from there.
    3. Ask Windows for the feature's state, and act only on "Disabled".

  Exit codes (the installer reads these):
     0  Already on. Nothing was changed.
    10  Already switched on earlier and waiting for a restart. Nothing was changed.
    11  Switched on now. Windows must restart before it works.
    12  Switched on now. No restart needed.
    20  Not available on this Windows (Home edition, or too old).
    30  Windows refused or failed to turn it on.
    31  A different change is waiting for a restart. Nothing was changed.
    40  Administrator approval was not given. Nothing was changed.

  A short log is written to %TEMP%\WebSentinel-sandbox-setup.log.
#>
[CmdletBinding()]
param(
    # Do not ask for administrator approval (used by the tests and by the elevated copy of this script).
    [switch]$NoElevate,
    [string]$LogFile = (Join-Path $env:TEMP 'WebSentinel-sandbox-setup.log'),
    # The launcher that exists only while the feature is on. A parameter so a test can point it elsewhere.
    [string]$LauncherPath = (Join-Path $env:windir 'System32\WindowsSandbox.exe')
)

$FeatureName = 'Containers-DisposableClientVM'

function Write-Log([string]$Message) {
    try { Add-Content -Path $LogFile -Value ('{0:s}  {1}' -f (Get-Date), $Message) -ErrorAction Stop } catch { }
    Write-Host $Message
}

function Test-IsAdministrator {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# What to do for each state Windows can report. Only "Disabled" ever leads to a change.
function Get-SandboxPlan([string]$State) {
    switch ($State) {
        'Enabled'        { return 'AlreadyEnabled' }
        'EnablePending'  { return 'AlreadyPending' }
        'DisablePending' { return 'DisablePending' }
        'Disabled'       { return 'Enable' }
        default          { return 'Unsupported' }
    }
}

# Run this same script again with administrator rights and hand back its exit code.
function Invoke-Elevated {
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath),
                   '-NoElevate', '-LogFile', ('"{0}"' -f $LogFile), '-LauncherPath', ('"{0}"' -f $LauncherPath))
    try {
        $process = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $arguments `
                                 -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
    } catch {
        Write-Log ('Administrator approval was not given: ' + $_.Exception.Message)
        return 40
    }
    return [int]$process.ExitCode
}

function Invoke-SandboxSetup {
    # 1. Already on? Then there is nothing to do, and nothing is asked.
    if (Test-Path -LiteralPath $LauncherPath) {
        Write-Log 'Windows Sandbox is already enabled. Nothing to do.'
        return 0
    }

    # 2. Turning a Windows feature on needs administrator rights.
    if (-not (Test-IsAdministrator)) {
        if ($NoElevate) {
            Write-Log 'Administrator rights are needed to turn on Windows Sandbox.'
            return 40
        }
        Write-Log 'Asking for administrator approval.'
        return (Invoke-Elevated)
    }

    # 3. Ask Windows, and act only on "Disabled".
    try {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction Stop
        $state = [string]$feature.State
    } catch {
        Write-Log ('Windows Sandbox is not available on this Windows: ' + $_.Exception.Message)
        return 20
    }
    Write-Log ('Windows reports the feature as: ' + $state)

    switch (Get-SandboxPlan $state) {
        'AlreadyEnabled' { Write-Log 'Already enabled. Nothing to do.'; return 0 }
        'AlreadyPending' { Write-Log 'Already switched on and waiting for a restart. Nothing to do.'; return 10 }
        'DisablePending' { Write-Log 'Another change is waiting for a restart. Restart Windows and run this again.'; return 31 }
        'Unsupported'    { Write-Log 'Windows Sandbox is not available on this Windows.'; return 20 }
    }

    Write-Log 'Turning on Windows Sandbox. This can take a few minutes.'
    try {
        $result = Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -All -NoRestart -ErrorAction Stop
    } catch {
        Write-Log ('Windows could not turn it on: ' + $_.Exception.Message)
        return 30
    }
    if ($result.RestartNeeded) {
        Write-Log 'Done. Restart Windows to finish.'
        return 11
    }
    Write-Log 'Done. No restart needed.'
    return 12
}

# The DISM cmdlets only work in a 64-bit PowerShell. A 32-bit one on a 64-bit Windows hands over to the 64-bit one.
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess -and $MyInvocation.InvocationName -ne '.') {
    $sixtyFour = Join-Path $env:windir 'SysNative\WindowsPowerShell\v1.0\powershell.exe'
    $forward = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath), '-LogFile', ('"{0}"' -f $LogFile), '-LauncherPath', ('"{0}"' -f $LauncherPath))
    if ($NoElevate) { $forward += '-NoElevate' }
    $child = Start-Process -FilePath $sixtyFour -ArgumentList $forward -Wait -PassThru -NoNewWindow
    exit [int]$child.ExitCode
}

# Dot-sourcing this file (the tests do) loads the functions without running anything.
if ($MyInvocation.InvocationName -ne '.') {
    exit (Invoke-SandboxSetup)
}
