; C1 (Extension Analyzer): the "Turn on Windows Sandbox" option of the WebSentinel installer.
;
; The analyzer runs a suspicious extension inside Windows Sandbox, a disposable virtual machine. That is a
; Windows feature which is off by default, and turning it on needs administrator approval and a restart.
; This file adds one page after "Setup options" with a single checkbox. Ticking it runs
; resources\c1\enable-windows-sandbox.ps1 at the end of the install (see that file for what it does and
; the exit codes read below).
;
; It never turns the feature on twice:
;   * the page is skipped when Windows Sandbox is already on (the same test the app uses: the launcher
;     System32\WindowsSandbox.exe exists), so nothing is asked and nothing is run;
;   * it is checked again just before the script runs, and the script checks once more.
; When it was turned on (or was already waiting for a restart) the installer sets the reboot flag, so the
; Finish page asks whether to restart now or later; the analyzer uses the VM from the next start of Windows.
; Left unticked, and for silent installs (/S), nothing about Windows is changed. Uninstalling does not turn
; the feature off, because other programs may be using it.
;
; installer.nsh includes this file and calls the three pieces below.

!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"

; Only the installer pass uses these. Declared in the uninstaller pass they would raise NSIS warning 6001,
; which electron-builder treats as an error (same reason as in installer.nsh).
!ifndef BUILD_UNINSTALLER
  Var C1SbBox
  Var C1SbOn
  Var C1SbState     ; 0 = can be turned on, 1 = already on, 2 = not available on this Windows
!endif

!ifndef BUILD_UNINSTALLER

; Sets $C1SbState without changing anything.
Function C1SbDetect
  StrCpy $C1SbState 0

  ; On: the launcher exists. A 32-bit installer on 64-bit Windows reaches the real System32 as Sysnative.
  ${If} ${FileExists} "$WINDIR\Sysnative\WindowsSandbox.exe"
  ${OrIf} ${FileExists} "$SYSDIR\WindowsSandbox.exe"
    StrCpy $C1SbState 1
    Return
  ${EndIf}

  ; Not available: Home editions (EditionID starts with "Core") and Windows 10 before 1903 do not have the feature.
  ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" "EditionID"
  StrCpy $1 $0 4
  ${If} $1 == "Core"
    StrCpy $C1SbState 2
    Return
  ${EndIf}
  ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" "CurrentBuildNumber"
  ${If} $0 != ""
  ${AndIf} $0 < 18362
    StrCpy $C1SbState 2
  ${EndIf}
FunctionEnd

; The page. Skipped when there is nothing to choose.
Function C1SbCreate
  Call C1SbDetect
  ${If} $C1SbState == 1
    Abort
  ${EndIf}

  !insertmacro MUI_HEADER_TEXT "Extension Analyzer" "Windows Sandbox gives the analyzer a disposable virtual machine."
  nsDialogs::Create 1018
  Pop $0
  ${If} $0 == error
    Abort
  ${EndIf}

  ${NSD_CreateLabel} 0 0 100% 36u "The Extension Analyzer can run a suspicious extension inside Windows Sandbox, a throwaway virtual machine that is destroyed afterwards. Without it, WebSentinel still works, but runs the extension in a less isolated mode on this PC."
  Pop $0

  ${NSD_CreateCheckbox} 0 46u 100% 12u "Turn on &Windows Sandbox for me (recommended)"
  Pop $C1SbBox

  ${If} $C1SbState == 2
    EnableWindow $C1SbBox 0
    ${NSD_CreateLabel} 12u 62u 95% 36u "Windows Sandbox is not available on this version of Windows. It needs Windows 10 or 11 Pro, Enterprise or Education. WebSentinel will use its less isolated mode."
    Pop $0
  ${Else}
    ${If} $C1SbOn == ${BST_CHECKED}
      ${NSD_Check} $C1SbBox
    ${EndIf}
    ${NSD_CreateLabel} 12u 62u 95% 48u "Windows will ask for administrator approval, and this PC needs a restart afterwards. Nothing is changed if you leave this unticked. You can turn it on later in Windows Features."
    Pop $0
  ${EndIf}

  nsDialogs::Show
FunctionEnd

Function C1SbLeave
  ${NSD_GetState} $C1SbBox $C1SbOn
FunctionEnd

; Run at the end of the install, only when the box was ticked.
Function C1SbEnable
  ; Look again: it may have been turned on since the page was shown, and it must never be turned on twice.
  Call C1SbDetect
  ${If} $C1SbState == 1
    DetailPrint "Windows Sandbox is already on. Nothing to do."
    Return
  ${EndIf}
  ${If} $C1SbState == 2
    DetailPrint "Windows Sandbox is not available on this version of Windows."
    Return
  ${EndIf}

  ; The Windows feature commands need the 64-bit PowerShell, which a 32-bit installer reaches as Sysnative.
  StrCpy $0 "$WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
  ${IfNot} ${FileExists} $0
    StrCpy $0 "$SYSDIR\WindowsPowerShell\v1.0\powershell.exe"
  ${EndIf}

  DetailPrint "Turning on Windows Sandbox. This can take a few minutes..."
  nsExec::ExecToLog '"$0" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\resources\c1\enable-windows-sandbox.ps1"'
  Pop $1

  StrCpy $2 ""
  ${If} $1 == 0
    DetailPrint "Windows Sandbox is already on."
  ${ElseIf} $1 == 12
    DetailPrint "Windows Sandbox is turned on."
  ${ElseIf} $1 == 11
  ${OrIf} $1 == 10
    ; The Finish page then offers the standard "restart now or later" choice.
    DetailPrint "Windows Sandbox is turned on and needs a restart."
    SetRebootFlag true
  ${ElseIf} $1 == 20
    DetailPrint "Windows Sandbox is not available on this version of Windows."
    StrCpy $2 "Windows Sandbox is not available on this version of Windows, so it was not turned on. WebSentinel will use its less isolated mode."
  ${ElseIf} $1 == 31
    DetailPrint "Another Windows change is waiting for a restart."
    StrCpy $2 "Another Windows change is waiting for a restart, so Windows Sandbox was not turned on. Restart this PC, then turn on Windows Sandbox in Windows Features."
  ${ElseIf} $1 == 40
    DetailPrint "Administrator approval was not given. Windows Sandbox was not turned on."
    StrCpy $2 "Administrator approval was not given, so Windows Sandbox was not turned on. WebSentinel will use its less isolated mode. You can turn it on later in Windows Features."
  ${Else}
    DetailPrint "Windows could not turn on Windows Sandbox."
    StrCpy $2 "Windows could not turn on Windows Sandbox. WebSentinel will use its less isolated mode. You can turn it on later in Windows Features. Details: $TEMP\WebSentinel-sandbox-setup.log"
  ${EndIf}

  ${If} $2 != ""
  ${AndIfNot} ${Silent}
    MessageBox MB_OK|MB_ICONINFORMATION "$2"
  ${EndIf}
  ClearErrors   ; nothing above is a reason to fail the install
FunctionEnd

!endif

!macro c1SandboxInstall
  ${If} $C1SbOn == ${BST_CHECKED}
    Call C1SbEnable
  ${EndIf}
!macroend
