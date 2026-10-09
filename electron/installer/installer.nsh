; Custom NSIS pieces for the WebSentinel installer (electron-builder `nsis.include`).
;
; Adds a "Setup options" page after the folder page that asks whether to create
; a Desktop shortcut, a Start Menu shortcut, and whether WebSentinel should
; always run as administrator. Shortcut creation is done here (the built-in
; shortcuts are switched off in package.json) so the answers are honoured.
; If a shortcut cannot be created, the user is offered a restart of the
; installer with administrator rights.

!include "nsDialogs.nsh"
!include "LogicLib.nsh"

Var ScDesktopBox
Var ScStartBox
Var ScAdminBox
Var ScDesktopOn
Var ScStartOn
Var ScAdminOn

; ── Defaults (also used for silent /S installs, where the page is skipped) ──
!macro customInit
  StrCpy $ScDesktopOn ${BST_CHECKED}
  StrCpy $ScStartOn   ${BST_CHECKED}
  StrCpy $ScAdminOn   ${BST_UNCHECKED}
!macroend

; ── The options page, shown after the install-folder page ──────────────────
!macro customPageAfterChangeDir
  Page custom ScOptionsCreate ScOptionsLeave
!macroend

!ifndef BUILD_UNINSTALLER
Function ScOptionsCreate
  !insertmacro MUI_HEADER_TEXT "Setup options" "Choose how WebSentinel is added to this computer."
  nsDialogs::Create 1018
  Pop $0
  ${If} $0 == error
    Abort
  ${EndIf}

  ${NSD_CreateLabel} 0 0 100% 24u "Select the shortcuts you want. You can leave any of them unticked."
  Pop $0

  ${NSD_CreateCheckbox} 0 30u 100% 12u "Create a &Desktop shortcut"
  Pop $ScDesktopBox
  ${If} $ScDesktopOn == ${BST_CHECKED}
    ${NSD_Check} $ScDesktopBox
  ${EndIf}

  ${NSD_CreateCheckbox} 0 48u 100% 12u "Create a &Start Menu shortcut"
  Pop $ScStartBox
  ${If} $ScStartOn == ${BST_CHECKED}
    ${NSD_Check} $ScStartBox
  ${EndIf}

  ${NSD_CreateCheckbox} 0 72u 100% 12u "Always run WebSentinel as &administrator"
  Pop $ScAdminBox
  ${If} $ScAdminOn == ${BST_CHECKED}
    ${NSD_Check} $ScAdminBox
  ${EndIf}

  ${NSD_CreateLabel} 12u 87u 95% 36u "Tick this only if WebSentinel fails to start or cannot reach the browser or sandbox without it. Windows will ask for permission each time the app opens."
  Pop $0

  nsDialogs::Show
FunctionEnd

Function ScOptionsLeave
  ${NSD_GetState} $ScDesktopBox $ScDesktopOn
  ${NSD_GetState} $ScStartBox   $ScStartOn
  ${NSD_GetState} $ScAdminBox   $ScAdminOn
FunctionEnd
!endif

; ── Create what was chosen ──────────────────────────────────────────────────
!macro customInstall
  ${If} $ScAdminOn != ${BST_CHECKED}
    DeleteRegValue SHCTX "Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" "$INSTDIR\${APP_EXECUTABLE_FILENAME}"
  ${EndIf}
  ClearErrors   ; a missing value above is not a failure

  ${If} $ScStartOn == ${BST_CHECKED}
    CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}.lnk" "$INSTDIR\${APP_EXECUTABLE_FILENAME}" "" "$INSTDIR\${APP_EXECUTABLE_FILENAME}" 0
  ${EndIf}

  ${If} $ScDesktopOn == ${BST_CHECKED}
    CreateShortCut "$DESKTOP\${PRODUCT_NAME}.lnk" "$INSTDIR\${APP_EXECUTABLE_FILENAME}" "" "$INSTDIR\${APP_EXECUTABLE_FILENAME}" 0
  ${EndIf}

  ; "Run as administrator" = the compatibility flag Windows reads when the exe
  ; is launched from any shortcut, the Start Menu or Explorer.
  ${If} $ScAdminOn == ${BST_CHECKED}
    WriteRegStr SHCTX "Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" "$INSTDIR\${APP_EXECUTABLE_FILENAME}" "~ RUNASADMIN"
  ${EndIf}

  ; Something above failed (usually a permissions problem): offer to retry as admin.
  ${If} ${Errors}
    MessageBox MB_YESNO|MB_ICONEXCLAMATION "WebSentinel could not finish setting up its shortcuts or settings, which usually means this installer needs administrator rights.$\r$\n$\r$\nRestart the installer as administrator now?" IDNO ScSkipElevate
      ExecShell "runas" "$EXEPATH"
      Quit
    ScSkipElevate:
  ${EndIf}
!macroend

; ── Remove them again on uninstall ──────────────────────────────────────────
!macro customUnInstall
  Delete "$SMPROGRAMS\${PRODUCT_NAME}.lnk"
  Delete "$DESKTOP\${PRODUCT_NAME}.lnk"
  DeleteRegValue SHCTX "Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" "$INSTDIR\${APP_EXECUTABLE_FILENAME}"
!macroend
