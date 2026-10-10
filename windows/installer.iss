; KeyBridge Windows installer (Inno Setup 6.3 or later).
;
;   iscc /DAppVersion=1.2.3 windows\installer.iss
;
; Input:  windows\build\KeyBridge.exe   (build.bat)
; Output: dist\KeyBridge-Windows-Setup.exe
;
; Per-user install (no admin prompt) into %LOCALAPPDATA%\Programs\KeyBridge.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

#define AppName       "KeyBridge"
#define AppExeName    "KeyBridge.exe"
#define AppPublisher  "Cameron MacLaurin"
#define AppURL        "https://github.com/cameronmaclaurin/KeyBridge"
; Must match KB_MUTEX_NAME and KB_WINDOW_CLASS in src\main.c.
#define AppMutexName  "Local\KeyBridgeClient"
#define AppWindowClass "KeyBridgeClientWnd"

[Setup]
; Never change AppId: it is how Windows and Inno Setup recognise upgrades.
AppId={{2E6550FF-4C8C-4A49-A08B-636892AB8489}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/issues
AppUpdatesURL={#AppURL}/releases
AppCopyright=Copyright (C) 2026 {#AppPublisher}
VersionInfoVersion={#AppVersion}
VersionInfoDescription={#AppName} Setup
VersionInfoProductName={#AppName}

; Per-user: no UAC prompt, installs for the current user only.
PrivilegesRequired=lowest
DefaultDirName={localappdata}\Programs\{#AppName}
DisableProgramGroupPage=yes
DisableDirPage=auto
UsePreviousAppDir=yes

; 64-bit Windows 10 or later.
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0

; A running KeyBridge is closed by the [Code] below before these checks run
; (InitializeSetup/InitializeUninstall happen before Setup/Uninstall look at
; AppMutex). Setup passes the name to OpenMutex unchanged, so the app's
; "Local\" session-namespace mutex is found exactly as the app created it;
; "Global\" is not needed for a per-user install in the user's own session.
AppMutex={#AppMutexName}
CloseApplications=yes
RestartApplications=no

SetupIconFile=..\assets\keybridge.ico
UninstallDisplayIcon={app}\{#AppExeName}
UninstallDisplayName={#AppName}
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
OutputDir=..\dist
OutputBaseFilename=KeyBridge-Windows-Setup

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "Start KeyBridge when I sign in"; GroupDescription: "Startup:"

[Files]
Source: "build\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Registry]
; Start at sign-in. The app's own "Start with Windows" menu item writes the
; same value; [Code] removes it on uninstall whoever wrote it.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "{#AppName}"; ValueData: """{app}\{#AppExeName}"""; Flags: uninsdeletevalue; Tasks: autostart
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueName: "{#AppName}"; Flags: deletevalue; Tasks: not autostart
; Remembered so the app's first-run setup dialog defaults to the same choice.
Root: HKCU; Subkey: "Software\{#AppName}"; ValueType: dword; ValueName: "StartAtSignIn"; ValueData: 1; Flags: uninsdeletekey; Tasks: autostart
Root: HKCU; Subkey: "Software\{#AppName}"; ValueType: dword; ValueName: "StartAtSignIn"; ValueData: 0; Flags: uninsdeletekey; Tasks: not autostart

[Run]
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Settings: Mac address and name, and the DPAPI-encrypted pairing key.
Type: filesandordirs; Name: "{userappdata}\{#AppName}"

[Code]
const
  KB_WM_CLOSE = $0010;

{ Ask a running KeyBridge to quit (it releases any held keys first) and wait
  briefly for it to go away. }
procedure CloseRunningKeyBridge();
var
  Wnd: HWND;
  I: Integer;
begin
  Wnd := FindWindowByClassName('{#AppWindowClass}');
  if Wnd = 0 then
    Exit;
  PostMessage(Wnd, KB_WM_CLOSE, 0, 0);
  for I := 1 to 50 do
  begin
    if not CheckForMutexes('{#AppMutexName}') then
      Exit;
    Sleep(100);
  end;
end;

function InitializeSetup(): Boolean;
begin
  CloseRunningKeyBridge();
  Result := True;
end;

function InitializeUninstall(): Boolean;
begin
  CloseRunningKeyBridge();
  Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    RegDeleteValue(HKEY_CURRENT_USER, 'Software\Microsoft\Windows\CurrentVersion\Run', '{#AppName}');
    RegDeleteValue(HKEY_CURRENT_USER, 'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run', '{#AppName}');
  end;
end;
