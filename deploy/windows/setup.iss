#define AppVersion "0.3.2"
[Setup]
AppId={{E9F177EC-7790-42A6-92C0-377DA6D29E9F}
AppName=R-TrustTunnel
AppVersion={#AppVersion}
AppPublisher=R-TrustTunnel
DefaultDirName={autopf}\R-TrustTunnel
DefaultGroupName=R-TrustTunnel
OutputDir=..\..\dist
OutputBaseFilename=R-TrustTunnel-Windows-x64-Setup
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.19041
PrivilegesRequired=admin
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\..\packaging\branding\icon.ico
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\rtrust.ico
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
ChangesAssociations=yes
[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
[Types]
Name: "native"; Description: "Native interface (no WebView runtime)"
Name: "webview"; Description: "WebView interface (requires Microsoft Edge WebView2)"
Name: "both"; Description: "Both interfaces"
Name: "custom"; Description: "Custom"; Flags: iscustom
[Components]
Name: "native"; Description: "Native desktop interface"; Types: native both
Name: "webview"; Description: "WebView desktop interface"; Types: webview both
[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; Flags: checkedonce
Name: "ttprotocol"; Description: "Open tt:// profile links with R-TrustTunnel"; Flags: unchecked
[Registry]
Root: HKLM; Subkey: "Software\Classes\tt"; ValueType: string; ValueName: ""; ValueData: "URL:TrustTunnel profile"; Tasks: ttprotocol; Check: CanRegisterTT; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\tt"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""; Tasks: ttprotocol; Check: CanRegisterTT
Root: HKLM; Subkey: "Software\Classes\tt\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{code:GetUiExe}"" ""%1"""; Tasks: ttprotocol; Check: CanRegisterTT
[Files]
Source: "..\..\packaging\branding\icon.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\dist\native-preview-windows\rtrust-update.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\dist\native-preview-windows\R-TrustTunnel.exe"; DestDir: "{app}"; Flags: ignoreversion; Components: native
Source: "..\..\dist\native-preview-windows\R-TrustTunnel-WebView.exe"; DestDir: "{app}"; Flags: ignoreversion; Components: webview
Source: "..\..\dist\native-preview-windows\rtrust-service.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\dist\native-preview-windows\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\dist\native-preview-windows\WINTUN-LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\scripts\install-windows-service.ps1"; DestDir: "{app}"; Flags: ignoreversion
[Icons]
Name: "{group}\R-TrustTunnel Native"; Filename: "{app}\R-TrustTunnel.exe"; Components: native; IconFilename: "{app}\rtrust.ico"
Name: "{group}\R-TrustTunnel WebView"; Filename: "{app}\R-TrustTunnel-WebView.exe"; Components: webview; IconFilename: "{app}\rtrust.ico"
Name: "{autodesktop}\R-TrustTunnel"; Filename: "{code:GetUiExe}"; Tasks: desktopicon; IconFilename: "{app}\rtrust.ico"
[Run]
Filename: "{code:GetUiExe}"; Description: "Launch R-TrustTunnel"; Flags: nowait postinstall skipifsilent runasoriginaluser; Check: CanLaunch
[Code]
var AccountPage: TInputQueryWizardPage;
    ServiceReady: Boolean;
function GetUiExe(Param: String): String;
begin
  if WizardIsComponentSelected('native') then Result := ExpandConstant('{app}\R-TrustTunnel.exe')
  else Result := ExpandConstant('{app}\R-TrustTunnel-WebView.exe');
end;
function WebViewAvailable(): Boolean;
var Version: String;
begin
  Result := RegQueryStringValue(HKLM32, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', Version) and (Version <> '') and (Version <> '0.0.0.0');
  if not Result then Result := RegQueryStringValue(HKCU, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', Version) and (Version <> '') and (Version <> '0.0.0.0');
end;
function CanLaunch(): Boolean;
begin
  Result := ServiceReady;
end;
function GetCustomSetupExitCode(): Integer;
begin
  if ServiceReady then Result := 0 else Result := 1;
end;
function CanRegisterTT(): Boolean;
var Existing: String;
begin
  Result := not RegQueryStringValue(HKLM, 'Software\Classes\tt\shell\open\command', '', Existing);
  if not Result then Result := (Pos(ExpandConstant('{app}\R-TrustTunnel.exe'), Existing) > 0) or (Pos(ExpandConstant('{app}\R-TrustTunnel-WebView.exe'), Existing) > 0);
end;
function RunService(Action: String): Boolean;
var Code: Integer; Args: String;
begin
  Args := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ExpandConstant('{app}\install-windows-service.ps1') + '" -Action ' + Action;
  if Action = 'Install' then Args := Args + ' -Source "' + ExpandConstant('{app}') + '" -AllowedAccount "' + AccountPage.Values[0] + '"';
  Result := ExecAndLogOutput(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), Args, '', SW_HIDE, ewWaitUntilTerminated, Code, nil) and (Code = 0);
  Log('VPN service ' + Action + ' exit code: ' + IntToStr(Code));
end;
procedure InitializeWizard();
begin
  AccountPage := CreateInputQueryPage(wpSelectDir, 'Windows account', 'Choose the account allowed to control VPN', 'Use COMPUTER\username or DOMAIN\username. This account runs the app without administrator privileges.');
  AccountPage.Add('Account:', False);
  AccountPage.Values[0] := ExpandConstant('{param:ACCOUNT|}') ;
  if AccountPage.Values[0] = '' then AccountPage.Values[0] := GetEnv('USERDOMAIN') + '\' + GetUserNameString;
end;
function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = wpSelectComponents then begin
    Result := WizardIsComponentSelected('native') or WizardIsComponentSelected('webview');
    if not Result then MsgBox('Select at least one interface.', mbError, MB_OK);
    if Result and WizardIsComponentSelected('webview') and not WebViewAvailable() then begin
      Result := False;
      MsgBox('Install Microsoft Edge WebView2 Evergreen Runtime before selecting WebView, or select Native.', mbError, MB_OK);
    end;
  end;
  if CurPageID = AccountPage.ID then begin
    Result := (Length(AccountPage.Values[0]) > 0) and (Pos('"', AccountPage.Values[0]) = 0) and (Pos(#13, AccountPage.Values[0]) = 0) and (Pos(#10, AccountPage.Values[0]) = 0);
    if not Result then MsgBox('Enter a valid Windows account name.', mbError, MB_OK);
  end;
end;
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then begin
    if not NextButtonClick(AccountPage.ID) then RaiseException('Invalid Windows account');
    ServiceReady := RunService('Install');
    if not ServiceReady then RaiseException('VPN service installation failed. See setup log; no VPN connection was started.');
  end;
end;
function InitializeUninstall(): Boolean;
begin
  Result := RunService('Remove');
  if not Result then MsgBox('Cannot safely recover/remove the VPN service. Uninstall stopped; files retained for recovery.', mbError, MB_OK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var Users: TArrayOfString; I: Integer; Key, Value, Expected: String;
begin
  if CurUninstallStep <> usPostUninstall then Exit;
  Expected := '"' + ExpandConstant('{app}\R-TrustTunnel.exe') + '" --autostart';
  { Only this installation's dedicated value in already loaded user hives.
    Never mount other users' hives or remove other startup commands. }
  if RegGetSubkeyNames(HKU, '', Users) then
    for I := 0 to GetArrayLength(Users) - 1 do begin
      Key := Users[I] + '\Software\Microsoft\Windows\CurrentVersion\Run';
      if RegQueryStringValue(HKU, Key, 'RTrustTunnel', Value) then
        if CompareText(Value, Expected) = 0 then
          if not RegDeleteValue(HKU, Key, 'RTrustTunnel') then
            Log('Could not remove this installation startup value');
    end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if not (WizardIsComponentSelected('native') or WizardIsComponentSelected('webview')) then Result := 'Select at least one interface.';
  if WizardIsComponentSelected('webview') and not WebViewAvailable() then Result := 'Microsoft Edge WebView2 Evergreen Runtime is required.';
end;
