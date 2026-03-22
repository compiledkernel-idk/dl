Unicode true
RequestExecutionLevel user
ManifestDPIAware true
SetCompressor /SOLID lzma

!ifndef VERSION
!define VERSION "0.1.0"
!endif

!ifndef BIN_PATH
!define BIN_PATH "dl.exe"
!endif

!ifndef OUTFILE_NAME
!define OUTFILE_NAME "dl-setup.exe"
!endif

InstallDir "$LOCALAPPDATA\Programs\dl"
Name "dl"
OutFile "${OUTFILE_NAME}"
ShowInstDetails show
ShowUninstDetails show
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

!include "WinMessages.nsh"

Function StrStr
  Exch $R1
  Exch
  Exch $R2
  Push $R3
  Push $R4
  Push $R5
  StrLen $R3 $R1
  StrCpy $R4 0
loop:
  StrCpy $R5 $R2 $R3 $R4
  StrCmp $R5 $R1 done
  StrCmp $R5 "" notfound
  IntOp $R4 $R4 + 1
  Goto loop
done:
  StrCpy $R1 $R2 "" $R4
  Goto exit
notfound:
  StrCpy $R1 ""
exit:
  Pop $R5
  Pop $R4
  Pop $R3
  Pop $R2
  Exch $R1
FunctionEnd

Function BroadcastEnv
  System::Call 'user32::SendMessageTimeoutW(p 0xffff, i ${WM_SETTINGCHANGE}, p 0, w "Environment", i 2, i 5000, *p .r0)'
FunctionEnd

Function AddToPath
  Exch $0
  Push $1
  Push $2
  ReadRegStr $1 HKCU "Environment" "Path"
  StrCmp $1 "" write_new
  Push ";$1;"
  Push ";$0;"
  Call StrStr
  Pop $2
  StrCmp $2 "" 0 done
  StrCpy $1 "$1;$0"
  WriteRegExpandStr HKCU "Environment" "Path" "$1"
  Call BroadcastEnv
  Goto done
write_new:
  WriteRegExpandStr HKCU "Environment" "Path" "$0"
  Call BroadcastEnv
done:
  Pop $2
  Pop $1
  Pop $0
FunctionEnd

Function un.RemoveFromPath
  Push $0
  Push $1
  Push $2
  Push $3
  Push $4
  ReadRegStr $0 HKCU "Environment" "Path"
  StrCmp $0 "" done
  StrCpy $1 ""
next_token:
  StrCmp $0 "" write_back
  StrCpy $2 0
find_end:
  StrCpy $3 $0 1 $2
  StrCmp $3 ";" token_done
  StrCmp $3 "" token_done
  IntOp $2 $2 + 1
  Goto find_end
token_done:
  StrCpy $4 $0 $2
  StrCmp $3 "" 0 +2
  StrCpy $0 ""
  StrCmp $3 "" 0 +2
  Goto handle_token
  StrCpy $0 $0 "" $2
  StrCpy $0 $0 "" 1
handle_token:
  StrCmp $4 "$INSTDIR" next_token
  StrCmp $4 "" next_token
  StrCmp $1 "" 0 +2
  StrCpy $1 "$4"
  StrCmp $1 "$4" next_token
  StrCpy $1 "$1;$4"
  Goto next_token
write_back:
  WriteRegExpandStr HKCU "Environment" "Path" "$1"
  Call un.BroadcastEnv
done:
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
FunctionEnd

Function un.BroadcastEnv
  System::Call 'user32::SendMessageTimeoutW(p 0xffff, i ${WM_SETTINGCHANGE}, p 0, w "Environment", i 2, i 5000, *p .r0)'
FunctionEnd

Section
  SetOutPath "$INSTDIR"
  File "${BIN_PATH}"
  WriteUninstaller "$INSTDIR\uninstall.exe"
  Push "$INSTDIR"
  Call AddToPath
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\dl" "DisplayName" "dl"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\dl" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\dl" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\dl" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\dl" "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\dl" "NoRepair" 1
SectionEnd

Section "Uninstall"
  Call un.RemoveFromPath
  Delete "$INSTDIR\dl.exe"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\dl"
SectionEnd
