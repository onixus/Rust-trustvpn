#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidateSet('Install','Remove')][string]$Action='Install',
    [string]$Source='',
    [string]$AllowedAccount='',
    [string]$AllowedSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
)
$ErrorActionPreference='Stop'
if (-not $Source) { $Source=$PSScriptRoot }
$serviceName='RTrustTunnel'
$destination=Join-Path $env:ProgramFiles 'RTrustTunnel Service'
$binary=Join-Path $destination 'rtrust-service.exe'
$existing=Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
if ($existing -and -not $existing.PathName.StartsWith('"'+$binary+'" ')) { throw 'Existing service has an unexpected binary path; refusing to replace it' }
if (Test-Path $destination) {
    if ((Get-Item $destination -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing a reparse-point installation directory' }
}
if ($Action -eq 'Remove') {
    if ($existing) {
        Stop-Service $serviceName
        (Get-Service $serviceName).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
        & $binary --recover
        if ($LASTEXITCODE) { & $binary --disable-always-on }
        if ($LASTEXITCODE) { throw 'VPN recovery failed; keep service installed for recovery' }
        & sc.exe delete $serviceName
        if ($LASTEXITCODE) { throw 'Service removal failed' }
    }
    if (Test-Path $destination) { Remove-Item $destination -Recurse -Force }
    return
}
if (Test-Path (Join-Path $destination 'always-on.rtrust')) { throw 'Disable always-on in the client before upgrading the service' }
if ($AllowedAccount) { $AllowedSid=(New-Object Security.Principal.NTAccount($AllowedAccount)).Translate([Security.Principal.SecurityIdentifier]).Value }
if ($AllowedSid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { throw 'Expected desktop account SID (S-1-5-21-...)' }
foreach ($name in @('rtrust-service.exe','wintun.dll')) {
    if (-not (Test-Path (Join-Path $Source $name) -PathType Leaf)) { throw "Missing $name" }
}
$sig=Get-AuthenticodeSignature (Join-Path $Source 'wintun.dll')
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notlike '*WireGuard*') { throw 'Wintun must have a valid WireGuard signature' }
if ($existing) {
    Stop-Service $serviceName
    (Get-Service $serviceName).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
}
if ($existing) {
    & $binary --recover
    if ($LASTEXITCODE) { throw 'VPN recovery failed; refusing upgrade while guard remains' }
}
New-Item $destination -ItemType Directory -Force | Out-Null
# Explicit protected ACL before copying a SYSTEM executable or DLL.
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)')
Set-Acl $destination $acl
Copy-Item (Join-Path $Source 'rtrust-service.exe') $binary -Force
Copy-Item (Join-Path $Source 'wintun.dll') (Join-Path $destination 'wintun.dll') -Force
$binPath='"'+$binary+'" '+$AllowedSid
if ($existing) {
    $changed=Invoke-CimMethod -InputObject $existing -MethodName Change -Arguments @{PathName=$binPath;StartName='LocalSystem';StartMode='Automatic'}
    if ($changed.ReturnValue -ne 0) { throw "SCM configuration failed: $($changed.ReturnValue)" }
} else {
    New-Service -Name $serviceName -BinaryPathName $binPath -StartupType Automatic -DisplayName 'R-TrustTunnel VPN Service' | Out-Null
}
# SCM restarts an unexpectedly terminated service so the normal GUI can recover
# the persistent guard without asking its user to launch an administrator shell.
& sc.exe failure $serviceName reset= 86400 actions= restart/2000/restart/5000/restart/10000
if ($LASTEXITCODE) { throw 'Cannot configure service crash recovery' }
# Grant this desktop account read-only SCM identity queries, never service mutation.
& sc.exe sdset $serviceName "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCLC;;;$AllowedSid)"
if ($LASTEXITCODE) { throw 'Cannot protect SCM service permissions' }
Start-Service $serviceName
(Get-Service $serviceName).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
Write-Host "R-TrustTunnel service installed for $AllowedSid"
