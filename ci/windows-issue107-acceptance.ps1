# Manual installed-service acceptance, NOT a CI entry point. Run as elevated Admin,
# never SYSTEM, only after immutable-head review and explicit human swap consent.
# Build all three artifacts as Admin beforehand in the protected build chain.
# Default is preflight-only; -ExecuteSwap explicitly permits the bounded swap.
# Canonical ProgramData journal is ALWAYS LEFT INTACT, including on PASS.
# REQUIRED BEFORE LAUNCH: an independently verified trusted NATIVE parent must
# supply a clean explicit environment BEFORE CLR/PowerShell initialization and
# launch the trusted x64 host as -NoProfile -NonInteractive -File <source script>.
# Do not inherit user-controlled runtime/profiler/startup settings. This script
# cannot establish that precondition or undo code loaded before its first line.
# Its inherited-environment check is after-the-fact detection ONLY, not proof of
# a clean CLR startup. Runtime execution remains BLOCKED without that proof.
# The exact host argv excludes -ExecutionPolicy. Independently verify an already
# allowed process policy before launch; do not change registry/global policy or
# relax argv to get past a blocked -File invocation.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-f]{32}$')][string]$Authorize,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$OriginalSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$WintunSha256,
    [Parameter(Mandatory=$true)][string]$CandidatePath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$CandidateSha256,
    [Parameter(Mandatory=$true)][string]$StartTestPath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$StartTestSha256,
    [Parameter(Mandatory=$true)][string]$JournalTestPath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$JournalTestSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$ExpectedRevision,
    [Parameter(Mandatory=$true)][string]$SourceDirectory,
    [Parameter(Mandatory=$true)][string]$ProtectedBuildRoot,
    [Parameter(Mandatory=$true)][string]$GitPath,
    [switch]$ExecuteSwap
)
# Parser/parameter-binding errors occur before this trap: caller must suppress
# raw stderr and perform a separate parser gate before invoking this script.
trap { [Console]::Out.WriteLine('FAIL: installed launcher runtime (details suppressed)'); exit 1 }
Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Demand([bool]$Condition) { if (-not $Condition) { throw 'installed acceptance assertion=false' } }
Demand ([Environment]::Is64BitProcess)
# Capture BEFORE clearing anything. Absence here cannot prove pre-CLR cleanliness.
$inheritedEnvironment=[Environment]::GetEnvironmentVariables('Process')
foreach ($name in $inheritedEnvironment.Keys) {
    $name=[string]$name
    if ($name.StartsWith('COR_',[StringComparison]::OrdinalIgnoreCase) -or
        $name.StartsWith('CORECLR_',[StringComparison]::OrdinalIgnoreCase) -or
        $name.StartsWith('COMPLUS_',[StringComparison]::OrdinalIgnoreCase) -or
        $name.StartsWith('DOTNET_',[StringComparison]::OrdinalIgnoreCase) -or
        $name.Equals('__PSLockdownPolicy',[StringComparison]::OrdinalIgnoreCase) -or
        $name.Equals('__COMPAT_LAYER',[StringComparison]::OrdinalIgnoreCase)) {
        [Console]::Out.WriteLine('BLOCKED: INHERITED_RUNTIME_ENVIRONMENT_UNSAFE; detection is not pre-CLR clean-launch proof')
        exit 1
    }
}
$inheritedEnvironment=$null
# Bootstrap uses only framework APIs/core cmdlets: no autoload or Add-Type yet.
$PSModuleAutoLoadingPreference='None'
$systemSid='S-1-5-18'; $adminSid='S-1-5-32-544'
$trustedInstallerSid='S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
Demand ($identity.User.Value -ne $systemSid)
Demand ([Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
$systemDirectory=[Environment]::SystemDirectory
$windowsDirectory=[IO.Directory]::GetParent($systemDirectory).FullName
$trustedShell=$systemDirectory+'\WindowsPowerShell\v1.0'
Demand ($PSHOME.Equals($trustedShell,[StringComparison]::OrdinalIgnoreCase))
Demand ([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName.Equals(($trustedShell+'\powershell.exe'),[StringComparison]::OrdinalIgnoreCase))
$hostArguments=[Environment]::GetCommandLineArgs()
# No host options (including -Command) may precede/interleave this exact shape.
Demand ($hostArguments.Length -ge 5)
Demand ($hostArguments[1] -ieq '-NoProfile' -and $hostArguments[2] -ieq '-NonInteractive' -and $hostArguments[3] -ieq '-File')
Demand ([IO.Path]::GetFullPath($hostArguments[4]).Equals([IO.Path]::GetFullPath($PSCommandPath),[StringComparison]::OrdinalIgnoreCase))
Demand ([IO.Path]::IsPathRooted($SourceDirectory))
$launcherSource=[IO.Path]::GetFullPath([IO.Path]::Combine([IO.Path]::GetFullPath($SourceDirectory),'ci\windows-issue107-acceptance.ps1'))
Demand ([IO.Path]::GetFullPath($PSCommandPath).Equals($launcherSource,[StringComparison]::OrdinalIgnoreCase))
function BootstrapAcl([string]$Path,[bool]$Directory,[bool]$Private,[bool]$Ancestor=$false) {
    Demand (([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::ReparsePoint) -eq 0)
    $item=if ($Directory) { [IO.DirectoryInfo]::new($Path) } else { [IO.FileInfo]::new($Path) }
    $acl=$item.GetAccessControl()
    Demand (@($systemSid,$adminSid,$trustedInstallerSid) -contains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value)
    $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    $mask=if ($Ancestor) { 0x100d0040 } else { 0x500d0156 }
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and
            ([int64]$rule.FileSystemRights -band $mask) -ne 0) {
            Demand (@($systemSid,$adminSid,$trustedInstallerSid) -contains $rule.IdentityReference.Value)
        }
    }
    if ($Private) {
        Demand ($acl.AreAccessRulesProtected -and $rules.Count -eq 2)
        foreach ($sid in @($systemSid,$adminSid)) {
            $found=@($rules | Microsoft.PowerShell.Core\Where-Object { $_.IdentityReference.Value -eq $sid })
            Demand ($found.Count -eq 1 -and $found[0].AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow)
            Demand ([int64]$found[0].FileSystemRights -eq [int64][Security.AccessControl.FileSystemRights]::FullControl)
        }
    }
}
function BootstrapAncestors([string]$Path) {
    $current=[IO.Path]::GetFullPath($Path)
    while (-not [string]::IsNullOrEmpty($current)) {
        BootstrapAcl $current $true $false $true
        $current=[IO.Path]::GetDirectoryName($current)
    }
}
Demand ([IO.Path]::IsPathRooted($ProtectedBuildRoot))
$ProtectedBuildRoot=[IO.Path]::GetFullPath($ProtectedBuildRoot).TrimEnd('\')
Demand ([IO.Path]::GetPathRoot($ProtectedBuildRoot) -match '^[A-Za-z]:\\$')
Demand ([IO.DriveInfo]::new([IO.Path]::GetPathRoot($ProtectedBuildRoot)).DriveType -eq [IO.DriveType]::Fixed)
BootstrapAncestors $ProtectedBuildRoot
BootstrapAcl $ProtectedBuildRoot $true $true
$bootstrap= $ProtectedBuildRoot+'\RTrustCompiler-'+$Authorize
Demand (-not [IO.Directory]::Exists($bootstrap) -and -not [IO.File]::Exists($bootstrap))
$bootstrapSd=[Security.AccessControl.DirectorySecurity]::new()
$bootstrapSd.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
# Framework overload passes the initial SD to CreateDirectory, never creates public-first.
[void][IO.Directory]::CreateDirectory($bootstrap,$bootstrapSd)
BootstrapAcl $bootstrap $true $true
$programData=[Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$cleanEnvironment=@{ SystemRoot=$windowsDirectory; windir=$windowsDirectory; SystemDrive=[IO.Path]::GetPathRoot($windowsDirectory).TrimEnd('\');
    PATH=$systemDirectory; PATHEXT='.EXE;.COM'; COMSPEC=$systemDirectory+'\cmd.exe'; TEMP=$bootstrap; TMP=$bootstrap;
    HOME=$bootstrap; USERPROFILE=$bootstrap; APPDATA=$bootstrap; LOCALAPPDATA=$bootstrap; ProgramData=$programData;
    PSModulePath=$trustedShell+'\Modules' }
foreach ($key in @([Environment]::GetEnvironmentVariables().Keys)) { [Environment]::SetEnvironmentVariable([string]$key,$null,'Process') }
foreach ($key in $cleanEnvironment.Keys) { [Environment]::SetEnvironmentVariable($key,$cleanEnvironment[$key],'Process') }
[Environment]::CurrentDirectory=$bootstrap
BootstrapAncestors $trustedShell
BootstrapAcl $trustedShell $true $false
foreach ($module in @('Microsoft.PowerShell.Utility','Microsoft.PowerShell.Security','Microsoft.PowerShell.Management','CimCmdlets','ScheduledTasks')) {
    $moduleDirectory=$trustedShell+'\Modules\'+$module
    BootstrapAncestors $moduleDirectory
    $queue=[Collections.Generic.Queue[string]]::new(); $queue.Enqueue($moduleDirectory); $entries=0
    while ($queue.Count -gt 0) {
        $directory=$queue.Dequeue(); BootstrapAcl $directory $true $false
        foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
            $entries++; Demand ($entries -le 4096)
            $directoryEntry=([IO.File]::GetAttributes($entry) -band [IO.FileAttributes]::Directory) -ne 0
            BootstrapAcl $entry $directoryEntry $false
            if ($directoryEntry) { $queue.Enqueue($entry) }
        }
    }
    $manifest=$moduleDirectory+'\'+$module+'.psd1'
    Microsoft.PowerShell.Core\Import-Module -Name $manifest -Force -ErrorAction Stop
}
Microsoft.PowerShell.Management\Set-Location -LiteralPath $bootstrap
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class RTrust107Installed {
    [StructLayout(LayoutKind.Sequential)] public struct SA { public int Length; public IntPtr Descriptor; public int Inherit; }
    [StructLayout(LayoutKind.Sequential)] public struct INFO {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool CreateDirectoryW(string path, ref SA attributes);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetFileInformationByHandle(IntPtr handle, out INFO facts);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] public static extern uint GetSystemDirectoryW(StringBuilder buffer, uint size);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] public static extern uint GetWindowsDirectoryW(StringBuilder buffer, uint size);
    [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] public static extern uint GetDriveTypeW(string root);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, StringBuilder image, ref uint length);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern uint GetNamedSecurityInfoW(string name, int type, uint information, out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(IntPtr descriptor, uint revision, uint information, out IntPtr text, out uint length);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
    public static string Descriptor(string path) {
        IntPtr owner, group, dacl, sacl, descriptor, text=IntPtr.Zero;
        // Owner, group, DACL and mandatory label; no privilege enabling or audit SACL read.
        if (GetNamedSecurityInfoW(path,1,0x17,out owner,out group,out dacl,out sacl,out descriptor)!=0)
            throw new InvalidOperationException("SD read=false");
        try {
            uint length;
            if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor,1,0x17,out text,out length))
                throw new InvalidOperationException("SD conversion=false");
            return Marshal.PtrToStringUni(text);
        } finally { if (text!=IntPtr.Zero) LocalFree(text); LocalFree(descriptor); }
    }
}
'@
$systemSid='S-1-5-18'; $adminSid='S-1-5-32-544'
$trustedInstallerSid='S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
Demand ($identity.User.Value -ne $systemSid)
Demand ([Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
$buffer=[Text.StringBuilder]::new(32768)
Demand ([RTrust107Installed]::GetSystemDirectoryW($buffer,32768) -gt 0)
$systemDirectory=$buffer.ToString()
$buffer=[Text.StringBuilder]::new(32768)
Demand ([RTrust107Installed]::GetWindowsDirectoryW($buffer,32768) -gt 0)
$windowsDirectory=$buffer.ToString()
$programData=[Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$pins=[Collections.Generic.List[IntPtr]]::new()
$stage=$null; $taskName=$null; $taskRegistered=$false; $taskRegistrationAttempted=$false; $registeredCom=$null; $armed=$false
$mutationStarted=$false
$swapped=$false; $restored=$false; $passed=$false; $blocked=$false; $canCleanup=$true
$watch=[Diagnostics.Stopwatch]::new()

function NoReparse([string]$Path) {
    Demand (([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::ReparsePoint) -eq 0)
}
function PinDirectory([string]$Path) {
    $handle=[RTrust107Installed]::CreateFileW($Path,0x20080,3,[IntPtr]::Zero,3,0x02200000,[IntPtr]::Zero)
    Demand ($handle -ne [IntPtr]::new(-1))
    $pins.Add($handle); NoReparse $Path
}
function PinFile([string]$Path,[bool]$Writable=$false) {
    $share=if ($Writable) { 3 } else { 1 }
    $handle=[RTrust107Installed]::CreateFileW($Path,0x80020080,$share,[IntPtr]::Zero,3,0x00200000,[IntPtr]::Zero)
    Demand ($handle -ne [IntPtr]::new(-1))
    $pins.Add($handle)
    $facts=[RTrust107Installed+INFO]::new()
    Demand ([RTrust107Installed]::GetFileInformationByHandle($handle,[ref]$facts))
    Demand (($facts.Attributes -band 0x410) -eq 0 -and $facts.Links -eq 1)
    return ('{0}:{1}:{2}' -f $facts.Volume,$facts.IndexHigh,$facts.IndexLow)
}
function PrivateAcl([string]$Path,[bool]$Protected) {
    NoReparse $Path
    $acl=Get-Acl -LiteralPath $Path
    Demand (@($systemSid,$adminSid) -contains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value)
    if ($Protected) { Demand $acl.AreAccessRulesProtected }
    $rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))
    Demand ($rules.Count -eq 2)
    foreach ($sid in @($systemSid,$adminSid)) {
        $matching=@($rules | Where-Object { $_.IdentityReference.Value -eq $sid })
        Demand ($matching.Count -eq 1)
        Demand ($matching[0].AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow)
        Demand ([int64]$matching[0].FileSystemRights -eq [int64][Security.AccessControl.FileSystemRights]::FullControl)
    }
}
function NoForeignDeleteChild([string]$Path) {
    NoReparse $Path
    $acl=Get-Acl -LiteralPath $Path
    $trusted=@($systemSid,$adminSid,$trustedInstallerSid)
    Demand ($trusted -contains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value)
    foreach ($rule in @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and
            (([int64]$rule.FileSystemRights -band 0x100d0040) -ne 0)) {
            Demand ($trusted -contains $rule.IdentityReference.Value)
        }
    }
}
function OsProtected([string]$Path) {
    NoReparse $Path
    $acl=Get-Acl -LiteralPath $Path
    $trusted=@($systemSid,$adminSid,$trustedInstallerSid)
    Demand ($trusted -contains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value)
    foreach ($rule in @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and
            (([int64]$rule.FileSystemRights -band 0x500d0156) -ne 0)) {
            Demand ($trusted -contains $rule.IdentityReference.Value)
        }
    }
}
function Ancestors([string]$Path) {
    $current=[IO.Path]::GetFullPath($Path)
    $drive=[IO.Path]::GetPathRoot($current)
    Demand ($drive -match '^[A-Za-z]:\\$' -and [RTrust107Installed]::GetDriveTypeW($drive) -eq 3)
    while (-not [string]::IsNullOrEmpty($current)) {
        PinDirectory $current; NoForeignDeleteChild $current
        $current=[IO.Path]::GetDirectoryName($current)
    }
}
function BuildChain([string]$Path,[bool]$IsFile) {
    $root=[IO.Path]::GetFullPath($ProtectedBuildRoot).TrimEnd('\')
    $full=[IO.Path]::GetFullPath($Path)
    Demand ($full.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase) -or $full.Equals($root,[StringComparison]::OrdinalIgnoreCase))
    $current=if ($IsFile) { [IO.Path]::GetDirectoryName($full) } else { $full }
    $chain=[Collections.Generic.List[string]]::new()
    while (-not $current.Equals($root,[StringComparison]::OrdinalIgnoreCase)) {
        $chain.Add($current); $current=[IO.Path]::GetDirectoryName($current)
        Demand (-not [string]::IsNullOrEmpty($current))
    }
    Ancestors $root; PrivateAcl $root $true
    for ($index=$chain.Count-1; $index -ge 0; $index--) { PinDirectory $chain[$index]; PrivateAcl $chain[$index] $false }
    if ($IsFile) { PrivateAcl $full $false; [void](PinFile $full) }
}
function NewPrivateDirectory([string]$Path) {
    $security=[Security.AccessControl.DirectorySecurity]::new()
    $security.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    $bytes=$security.GetSecurityDescriptorBinaryForm()
    $pin=[Runtime.InteropServices.GCHandle]::Alloc($bytes,[Runtime.InteropServices.GCHandleType]::Pinned)
    try {
        $attributes=[RTrust107Installed+SA]::new()
        $attributes.Length=[Runtime.InteropServices.Marshal]::SizeOf($attributes)
        $attributes.Descriptor=$pin.AddrOfPinnedObject()
        Demand ([RTrust107Installed]::CreateDirectoryW($Path,[ref]$attributes))
    } finally { $pin.Free() }
    try { PinDirectory $Path; PrivateAcl $Path $true }
    catch { $script:canCleanup=$false; throw 'protected stage readback=false' }
}
function Imports([string]$Path) {
    $bytes=[IO.File]::ReadAllBytes($Path)
    Demand ($bytes.Length -gt 256)
    function U16([int]$Offset) { Demand ($Offset -ge 0 -and $Offset+2 -le $bytes.Length); [BitConverter]::ToUInt16($bytes,$Offset) }
    function U32([int]$Offset) { Demand ($Offset -ge 0 -and $Offset+4 -le $bytes.Length); [BitConverter]::ToUInt32($bytes,$Offset) }
    Demand ((U16 0) -eq 0x5a4d)
    $pe=[int](U32 0x3c); Demand ((U32 $pe) -eq 0x4550)
    $sections=U16 ($pe+6); $optional=$pe+24
    Demand ((U16 $optional) -eq 0x20b)
    Demand ((U32 ($optional+108)) -ge 14)
    Demand ((U32 ($optional+112+13*8)) -eq 0)
    $sectionTable=$optional+(U16 ($pe+20))
    function Offset([uint32]$Rva) {
        if ($Rva -lt (U32 ($optional+60))) { return [int]$Rva }
        for ($i=0; $i -lt $sections; $i++) {
            $section=$sectionTable+$i*40; $start=U32 ($section+12); $raw=U32 ($section+16)
            if ($Rva -ge $start -and [uint64]$Rva -lt [uint64]$start+$raw) { return [int]((U32 ($section+20))+$Rva-$start) }
        }
        throw 'unmapped PE import=false'
    }
    $rva=U32 ($optional+120); Demand ($rva -ne 0); $position=Offset $rva
    $names=[Collections.Generic.List[string]]::new()
    for ($i=0; $i -lt 256; $i++) {
        $item=$position+$i*20; $name=U32 ($item+12)
        if ($name -eq 0) { return $names.ToArray() }
        $start=Offset $name; $end=$start
        while ($end -lt $bytes.Length -and $bytes[$end] -ne 0 -and $end-$start -lt 260) { $end++ }
        Demand ($end -lt $bytes.Length -and $bytes[$end] -eq 0)
        $text=[Text.Encoding]::ASCII.GetString($bytes,$start,$end-$start).ToLowerInvariant()
        Demand ($text -match '^[a-z0-9_-]+\.dll$'); $names.Add($text)
    }
    throw 'PE import bound=false'
}
function LoaderProof([string]$Executable) {
    OsProtected $systemDirectory; OsProtected $windowsDirectory
    $known=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $registry=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs'
    foreach ($property in $registry.PSObject.Properties) {
        if ($property.Value -is [string] -and $property.Value -match '^[a-zA-Z0-9_-]+\.dll$') { [void]$known.Add($property.Value) }
    }
    Demand ($known.Count -gt 0)
    $pending=[Collections.Generic.Queue[string]]::new()
    foreach ($name in @(Imports $Executable)) { $pending.Enqueue($name) }
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    while ($pending.Count -gt 0) {
        $name=$pending.Dequeue(); if (-not $seen.Add($name)) { continue }; Demand ($seen.Count -le 256)
        if ($known.Contains($name)) { continue }
        # Never exempt api-ms/ext-ms by name. Unverified logical mapping BLOCKS.
        $dll=Join-Path $systemDirectory $name; OsProtected $dll
        $signature=Get-AuthenticodeSignature -LiteralPath $dll
        Demand ($signature.Status -eq [Management.Automation.SignatureStatus]::Valid)
        Demand ($signature.SignerCertificate.Subject -match 'O=Microsoft Corporation(?:,|$)')
        foreach ($dependency in @(Imports $dll)) { $pending.Enqueue($dependency) }
    }
}
function RequireLoaderProof([string]$Path) {
    try { LoaderProof $Path }
    catch { $script:blocked=$true; Write-Output 'BLOCKED: LOADER_POLICY_UNPROVEN'; throw 'loader proof unavailable=false' }
}
function Hash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function TextHash([string]$Value) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))).Replace('-','') }
    finally { $sha.Dispose() }
}
function SddlHash([string]$Path) { TextHash ([RTrust107Installed]::Descriptor($Path)) }
function SafeLiteral([string]$Value) { Demand ($Value -match '^[A-Za-z0-9 :\\._()-]+$'); return $Value }
function Run([string]$Executable,[string]$Arguments,[int]$Milliseconds=40000,[bool]$AllowFailure=$false,[hashtable]$ExtraEnvironment=@{}) {
    $info=[Diagnostics.ProcessStartInfo]::new()
    $info.FileName=$Executable; $info.Arguments=$Arguments; $info.WorkingDirectory=$bootstrap
    $info.UseShellExecute=$false; $info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
    $info.EnvironmentVariables.Clear()
    foreach ($key in $cleanEnvironment.Keys) { $info.EnvironmentVariables[$key]=[string]$cleanEnvironment[$key] }
    foreach ($key in @('RTRUST_INSTALLED_ACCEPTANCE','RTRUST_INSTALLED_STAGE','RTRUST_INSTALLED_SNAPSHOT',
        'RTRUST_EXPLORER_PID','RTRUST_EXPLORER_CREATED','RTRUST_EXPLORER_SESSION','RTRUST_INSTALLED_PID1',
        'RTRUST_INSTALLED_PID2','RTRUST_INSTALLED_TRIGGER','RTRUST_INSTALLED_PHASE')) {
        $value=[Environment]::GetEnvironmentVariable($key,'Process')
        if ($null -ne $value) { $info.EnvironmentVariables[$key]=$value }
    }
    foreach ($key in $ExtraEnvironment.Keys) { $info.EnvironmentVariables[$key]=[string]$ExtraEnvironment[$key] }
    $p=[Diagnostics.Process]::new(); $p.StartInfo=$info
    try {
        Demand ($p.Start()); $stdout=$p.StandardOutput.ReadToEndAsync(); $stderr=$p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($Milliseconds)) {
            try { $p.Kill(); [void]$p.WaitForExit(10000) } catch { $script:canCleanup=$false }
            Demand $false
        }
        Demand $p.HasExited
        $text=$stdout.GetAwaiter().GetResult(); [void]$stderr.GetAwaiter().GetResult()
        if ($AllowFailure) { return [PSCustomObject]@{ Code=$p.ExitCode; Text=$text } }
        Demand ($p.ExitCode -eq 0)
        return $text
    } finally { $p.Dispose() }
}
function VerifySourceGit {
    # Never ask Git to open the source repository's config/includes, hooks, info
    # attributes, common-dir or worktree metadata. Inspect a private projection.
    Demand ([IO.Path]::IsPathRooted($GitPath))
    $git=[IO.Path]::GetFullPath($GitPath); [void](SafeLiteral $git)
    Demand ([IO.Path]::GetFileName($git) -ieq 'git.exe')
    $gitDirectory=[IO.Path]::GetDirectoryName($git)
    Demand (@('cmd','bin') -contains [IO.Path]::GetFileName($gitDirectory))
    $gitRoot=[IO.Path]::GetDirectoryName($gitDirectory)
    Ancestors $gitDirectory; OsProtected $gitRoot; [void](PinFile $git)
    # Git-for-Windows wrappers/helpers/DLLs must also be non-user-writable.
    $toolQueue=[Collections.Generic.Queue[string]]::new(); $toolQueue.Enqueue($gitRoot); $toolEntries=0
    while ($toolQueue.Count -gt 0) {
        $directory=$toolQueue.Dequeue(); PinDirectory $directory; OsProtected $directory
        foreach ($path in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
            $toolEntries++; Demand ($toolEntries -le 32768)
            Demand ([IO.Path]::GetFileName($path) -ine 'always-on.key')
            OsProtected $path
            if (([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::Directory) -ne 0) { $toolQueue.Enqueue($path) }
        }
    }
    $metadata=Join-Path $SourceDirectory '.git'
    Demand ([IO.Directory]::Exists($metadata)); BuildChain $metadata $false
    foreach ($unsupported in @('commondir','gitdir','worktrees','config.worktree')) {
        $path=Join-Path $metadata $unsupported
        Demand (-not [IO.File]::Exists($path) -and -not [IO.Directory]::Exists($path))
    }
    BuildChain (Join-Path $metadata 'config') $true # SD/pin only; never read its possibly private values.
    $headPath=Join-Path $metadata 'HEAD'; BuildChain $headPath $true
    Demand (([IO.FileInfo]::new($headPath)).Length -le 1024)
    $head=[IO.File]::ReadAllText($headPath)
    if ($head -match '\Aref: (refs/heads/[A-Za-z0-9._/-]+)\r?\n?\z') {
        $reference=$Matches[1]
        Demand (-not $reference.Contains('..') -and -not $reference.Contains('//') -and -not $reference.EndsWith('/'))
        $headPath=Join-Path $metadata $reference; BuildChain $headPath $true
        Demand (([IO.FileInfo]::new($headPath)).Length -le 1024)
        $head=[IO.File]::ReadAllText($headPath)
    }
    Demand ($head -match '\A[0-9a-f]{40}\r?\n?\z' -and $head.Trim() -ceq $ExpectedRevision)
    $index=Join-Path $metadata 'index'; BuildChain $index $true
    Demand (([IO.FileInfo]::new($index)).Length -ge 12 -and ([IO.FileInfo]::new($index)).Length -le 16777216)
    $objects=Join-Path $metadata 'objects'; BuildChain $objects $false
    foreach ($name in @('info\alternates','info\http-alternates')) {
        Demand (-not [IO.File]::Exists((Join-Path $objects $name)) -and -not [IO.Directory]::Exists((Join-Path $objects $name)))
    }
    $queue=[Collections.Generic.Queue[string]]::new(); $queue.Enqueue($objects); $entries=0
    while ($queue.Count -gt 0) {
        $directory=$queue.Dequeue(); PinDirectory $directory; PrivateAcl $directory $false
        foreach ($path in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
            $entries++; Demand ($entries -le 16384); NoReparse $path
            if (([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::Directory) -ne 0) { $queue.Enqueue($path) }
            else { PrivateAcl $path $false; [void](PinFile $path) }
        }
    }
    $verification=Join-Path $bootstrap 'git-verification'; NewPrivateDirectory $verification
    NewPrivateDirectory (Join-Path $verification 'refs') # Required even with detached HEAD and external objects.
    $hooks=Join-Path $verification 'empty-hooks'; NewPrivateDirectory $hooks
    $attributes=Join-Path $verification 'empty-attributes'; [IO.File]::WriteAllText($attributes,'')
    $utf8=[Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText((Join-Path $verification 'config'),"[core]`nrepositoryformatversion = 0`nbare = false`nfilemode = false`nsymlinks = false`n",$utf8)
    [IO.File]::WriteAllText((Join-Path $verification 'HEAD'),$ExpectedRevision+"`n",$utf8)
    [IO.File]::Copy($index,(Join-Path $verification 'index'),$false)
    $gitEnvironment=@{ GIT_CONFIG_NOSYSTEM='1'; GIT_CONFIG_SYSTEM='NUL'; GIT_CONFIG_GLOBAL='NUL';
        GIT_ATTR_NOSYSTEM='1'; GIT_NO_LAZY_FETCH='1'; GIT_TERMINAL_PROMPT='0'; GIT_OBJECT_DIRECTORY=$objects; ProgramData=$verification }
    foreach ($path in @($verification,$SourceDirectory,$hooks,$attributes)) { [void](SafeLiteral $path) }
    $arguments='--no-optional-locks --no-replace-objects --git-dir="{0}" --work-tree="{1}" -c core.fsmonitor=false -c core.hooksPath="{2}" -c core.attributesFile="{3}"' -f $verification,$SourceDirectory,$hooks,$attributes
    Demand ((Run $git ($arguments+' rev-parse HEAD') 40000 $false $gitEnvironment).Trim() -ceq $ExpectedRevision)
    $tracked=Run $git ($arguments+' ls-files --stage -z') 40000 $false $gitEnvironment
    foreach ($entry in $tracked.Split([char]0)) { Demand (-not $entry.StartsWith('160000 ')) }
    $tags=Run $git ($arguments+' ls-files -v -z') 40000 $false $gitEnvironment
    foreach ($entry in $tags.Split([char]0)) {
        if ($entry.Length -eq 0) { continue }
        # S means skip-worktree; lowercase tags mean assume-unchanged. Only ordinary H is accepted.
        Demand ($entry.StartsWith('H ',[StringComparison]::Ordinal))
    }
    Demand ([string]::IsNullOrWhiteSpace((Run $git ($arguments+' status --porcelain=v1 --untracked-files=all --ignore-submodules=all') 40000 $false $gitEnvironment)))
    foreach ($relative in $sourceInputs) {
        $path=Join-Path $SourceDirectory ($relative.Replace('/','\')); BuildChain $path $true; [void](SafeLiteral $path)
        # Do not trust index stat-cache cleanliness or invoke clean/smudge filters.
        $blob=(Run $git ($arguments+' rev-parse --verify "HEAD:'+ $relative+'"') 40000 $false $gitEnvironment).Trim()
        Demand ($blob -cmatch '\A[0-9a-f]{40}\z')
        $actual=(Run $git ($arguments+' hash-object --no-filters -- "'+$path+'"') 40000 $false $gitEnvironment).Trim()
        Demand ($actual -ceq $blob)
    }
}
function OsTool([string]$Name) {
    $path=Join-Path $systemDirectory $Name; OsProtected $path
    $signature=Get-AuthenticodeSignature -LiteralPath $path
    Demand ($signature.Status -eq [Management.Automation.SignatureStatus]::Valid)
    Demand ($signature.SignerCertificate.Subject -match 'O=Microsoft Corporation(?:,|$)')
    [void](PinFile $path); return $path
}
function RawCapture([string]$Tool,[string]$Arguments,[string]$Destination) {
    [void](SafeLiteral $Tool); [void](SafeLiteral $Destination)
    [void](Run $cmd ('/d /c ""{0}" {1} > "{2}" 2>nul"' -f $Tool,$Arguments,$Destination))
}
function Service {
    $services=@(Get-CimInstance Win32_Service -Filter "Name='RTrustTunnel'" -OperationTimeoutSec 5)
    Demand ($services.Count -eq 1)
    return $services[0]
}
function ConfigDigest {
    $s=Service
    TextHash (([ordered]@{ PathName=$s.PathName; StartName=$s.StartName; StartMode=$s.StartMode;
        ServiceType=$s.ServiceType; DesktopInteract=$s.DesktopInteract; ErrorControl=$s.ErrorControl;
        DelayedAutoStart=$s.DelayedAutoStart } | ConvertTo-Json -Compress))
}
function DnsDigest {
    $rows=@(Get-CimInstance -Namespace 'root/StandardCimv2' -ClassName MSFT_DNSClientServerAddress -OperationTimeoutSec 5 | ForEach-Object {
        '{0}:{1}:{2}' -f $_.InterfaceIndex,$_.AddressFamily,([string]::Join(',',@($_.ServerAddresses)))
    } | Sort-Object)
    TextHash ([string]::Join("`n",$rows))
}
function KeyMetadata {
    $path=Join-Path $installDirectory 'always-on.key'
    # Metadata ONLY. Never Get-FileHash, open, copy, remove or enumerate contents.
    if (-not [IO.File]::Exists($path)) { return 'absent' }
    NoReparse $path
    $info=[IO.FileInfo]::new($path)
    return (TextHash ('present:{0}:{1}' -f $info.Length,$info.LastWriteTimeUtc.Ticks))
}
function AbsentState {
    Demand (-not [IO.File]::Exists((Join-Path $installDirectory 'always-on.rtrust')))
    Demand (-not [IO.File]::Exists((Join-Path $installDirectory 'full-state.json')))
}
function Explorer {
    $all=@(Get-Process -Name explorer)
    Demand ($all.Count -eq 1)
    $explorer=$all[0]; $image=Join-Path $windowsDirectory 'explorer.exe'
    Demand ($explorer.Path.Equals($image,[StringComparison]::OrdinalIgnoreCase))
    $signature=Get-AuthenticodeSignature -LiteralPath $image
    Demand ($signature.Status -eq [Management.Automation.SignatureStatus]::Valid)
    Demand ($signature.SignerCertificate.Subject -match 'O=Microsoft Corporation(?:,|$)')
    Demand ($explorer.SessionId -eq [RTrust107Installed]::WTSGetActiveConsoleSessionId())
    $env:RTRUST_EXPLORER_PID=[string]$explorer.Id
    $env:RTRUST_EXPLORER_CREATED=[string]$explorer.StartTime.ToUniversalTime().ToFileTimeUtc()
    $env:RTRUST_EXPLORER_SESSION=[string]$explorer.SessionId
    $env:SystemRoot=$windowsDirectory
}
function QuietUi {
    $gui=@(Get-CimInstance Win32_Process -Filter "Name='R-TrustTunnel.exe' OR Name='R-TrustTunnel-WebView.exe' OR Name='rtrust-webview.exe' OR Name='rtrust-update.exe'" -Property ProcessId -OperationTimeoutSec 5)
    Demand ($gui.Count -eq 0)
}
function BeforeMutation {
    # Reserve eight minutes for bounded rollback and independent verification.
    Demand ($armed -and $watch.IsRunning -and $watch.Elapsed.TotalMinutes -lt 12)
    QuietUi
    AbsentState
    Demand ([DateTime]::UtcNow -lt $watchdogUtc.AddMinutes(-3))
    Demand (-not [IO.File]::Exists((Join-Path $stage 'rollback.started')))
    Demand (-not [IO.File]::Exists((Join-Path $stage 'rollback.failed')))
}
function Native([string]$Path,[string]$ExpectedHash,[string]$Test,[string[]]$Markers,[bool]$CheckDeadline=$true) {
    if ($CheckDeadline) { BeforeMutation }
    Demand ((Hash $Path) -eq $ExpectedHash.ToLowerInvariant())
    $result=Run $Path ('--ignored --exact {0} --nocapture --test-threads=1' -f $Test) 40000 $true
    $text=$result.Text
    foreach ($reason in @('BLOCKED: B_ACTIVE_LEASE','BLOCKED: GENUINE_EXPLORER_TOKEN_UNAVAILABLE','BLOCKED: C_REAL_OPEN_INCONCLUSIVE')) {
        if ($text.Contains($reason)) { $script:blocked=$true; Write-Output $reason; throw 'native blocked=false' }
    }
    Demand ($result.Code -eq 0)
    Demand ($text -match 'running 1 test' -and $text -match 'test result: ok\. 1 passed; 0 failed; 0 ignored;')
    Demand ($text -notmatch 'NOT RUN:')
    foreach ($marker in $Markers) { Demand ($text.Contains($marker)); Write-Output $marker }
}
function Snapshot([bool]$Capture,[bool]$CheckDeadline=$false) {
    AbsentState
    $env:RTRUST_INSTALLED_SNAPSHOT=if ($Capture) { 'capture' } else { 'compare' }
    Native $startTest $StartTestSha256 'wfp_net_snapshot' @('PASS: INSTALLED_IDLE_NETWORK_EQUAL') $CheckDeadline
}
function WaitService([string]$State,[int]$Seconds=30) {
    $timer=[Diagnostics.Stopwatch]::StartNew()
    do {
        $s=Service
        if ($s.State -eq $State) { return $s }
        Demand ($timer.Elapsed.TotalSeconds -lt $Seconds)
        Start-Sleep -Milliseconds 200
    } while ($true)
}
function ServiceProcess($Service) {
    Demand ($Service.ProcessId -ne 0)
    $handle=[RTrust107Installed]::OpenProcess(0x101000,$false,[uint32]$Service.ProcessId)
    Demand ($handle -ne [IntPtr]::Zero)
    $pins.Add($handle)
    $image=[Text.StringBuilder]::new(32768); $length=[uint32]32768
    Demand ([RTrust107Installed]::QueryFullProcessImageNameW($handle,0,$image,[ref]$length))
    Demand ($image.ToString().Equals($installedExe,[StringComparison]::OrdinalIgnoreCase))
    return $handle
}
function CandidateStart {
    BeforeMutation
    Demand ((Hash $installedExe) -eq $CandidateSha256.ToLowerInvariant())
    [void](Run $sc 'start RTrustTunnel' 15000)
    $s=WaitService 'Running'
    [void](ServiceProcess $s)
    return [uint32]$s.ProcessId
}
function CandidateStop {
    BeforeMutation
    $oldProcess=ServiceProcess (Service)
    $script:mutationStarted=$true
    [void](Run $sc 'stop RTrustTunnel' 15000)
    [void](WaitService 'Stopped')
    Demand ([RTrust107Installed]::WaitForSingleObject($oldProcess,30000) -eq 0)
    BeforeMutation
}
function SystemReceipt([string]$Name) {
    $path=Join-Path $stage $Name; NoReparse $path
    Demand ((Get-Acl -LiteralPath $path).GetOwner([Security.Principal.SecurityIdentifier]).Value -eq $systemSid)
    Demand (([IO.File]::ReadAllText($path)).Trim() -ceq $Authorize)
    [void](PinFile $path)
}
function TaskRun([string]$Receipt,[int]$Seconds) {
    Demand ((Hash $rollback) -eq $rollbackHash)
    $notBefore=[DateTime]::UtcNow.AddSeconds(-2)
    Start-ScheduledTask -TaskName $taskName
    $timer=[Diagnostics.Stopwatch]::StartNew()
    do {
        $task=Get-ScheduledTask -TaskName $taskName
        $info=Get-ScheduledTaskInfo -TaskName $taskName
        if ($task.State -ne 'Running' -and $info.LastRunTime.ToUniversalTime() -ge $notBefore -and
            [IO.File]::Exists((Join-Path $stage $Receipt))) {
            Demand ($info.LastTaskResult -eq 0); SystemReceipt $Receipt; return
        }
        if ([IO.File]::Exists((Join-Path $stage 'rollback.failed'))) { Demand $false }
        Demand ($timer.Elapsed.TotalSeconds -lt $Seconds)
        Start-Sleep -Milliseconds 250
    } while ($true)
}
function TaskSecurity($Task) {
    $descriptor=[Security.AccessControl.RawSecurityDescriptor]::new($Task.GetSecurityDescriptor(7))
    Demand (@($systemSid,$adminSid) -contains $descriptor.Owner.Value)
    Demand (($descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -ne 0)
    Demand ($descriptor.DiscretionaryAcl.Count -eq 2)
    foreach ($sid in @($systemSid,$adminSid)) {
        $rules=@($descriptor.DiscretionaryAcl | Where-Object {
            $_ -is [Security.AccessControl.CommonAce] -and $_.SecurityIdentifier.Value -eq $sid
        })
        Demand ($rules.Count -eq 1)
        Demand ($rules[0].AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessAllowed)
        Demand ($rules[0].AccessMask -eq 0x1f01ff)
    }
}
function LookupTask {
    try { return $taskFolder.GetTask($taskName) }
    catch {
        $failure=$_.Exception
        while ($null -ne $failure) {
            if ($failure -is [Runtime.InteropServices.COMException] -and $failure.ErrorCode -eq -2147024894) { return $null }
            $failure=$failure.InnerException
        }
        throw 'task lookup uncertain=false'
    }
}
function ConfirmTaskIdentity($Task) {
    # Needed only if RegisterTask threw after possibly committing on the server.
    # Never modify a coincident foreign task when ownership cannot be established.
    Demand ($Task.Name -ceq $taskName)
    $definition=$Task.Definition
    Demand ($definition.Actions.Count -eq 1 -and $definition.Actions.Item(1).Type -eq 0)
    $action=$definition.Actions.Item(1)
    Demand ($action.Path -ceq $cmd -and $action.Arguments -ceq $taskArguments -and $action.WorkingDirectory -ceq $systemDirectory)
    Demand (@($systemSid,'SYSTEM','NT AUTHORITY\SYSTEM') -contains $definition.Principal.UserId)
    Demand ($definition.Principal.LogonType -eq 5 -and $definition.Principal.RunLevel -eq 1)
    Demand ($definition.Triggers.Count -eq 1 -and $definition.Triggers.Item(1).Type -eq 1)
    Demand ([Math]::Abs(([DateTime]::Parse($definition.Triggers.Item(1).StartBoundary).ToUniversalTime()-$watchdogUtc).TotalSeconds) -le 3)
}
function CleanupBeforeMutation {
    $knownOwned=$taskRegistered; $disabled=$false; $absent=$false
    try {
        $own=$registeredCom
        if ($null -eq $own) { $own=LookupTask }
        if ($null -eq $own) {
            NoRollbackProcess; Start-Sleep -Milliseconds 250; NoRollbackProcess
            $script:taskRegistered=$false; $absent=$true
            Demand (-not [IO.File]::Exists((Join-Path $stage 'rollback.started')) -and -not [IO.File]::Exists((Join-Path $stage 'rollback.failed')))
            OriginalMetadata
            Write-Output 'PASS: PREMUTATION_TASK_CONFIRMED_ABSENT'
            return
        }
        if (-not $knownOwned) { ConfirmTaskIdentity $own; $knownOwned=$true }
        # Disable regardless of a failed SD check; never terminate an active instance.
        $own.Enabled=$false; Demand (-not $own.Enabled); $disabled=$true
        $timer=[Diagnostics.Stopwatch]::StartNew()
        while ($own.GetInstances(0).Count -ne 0) {
            Demand ($timer.Elapsed.TotalSeconds -lt 120)
            Start-Sleep -Milliseconds 250
        }
        NoRollbackProcess; Start-Sleep -Milliseconds 250
        Demand ($own.GetInstances(0).Count -eq 0 -and -not $own.Enabled)
        NoRollbackProcess
        # A clock jump/sleep may already have launched rollback before our mutation.
        # Do not claim an untouched original or discard its backup on that path.
        Demand (-not [IO.File]::Exists((Join-Path $stage 'rollback.started')) -and -not [IO.File]::Exists((Join-Path $stage 'rollback.failed')))
        OriginalMetadata
        $taskFolder.DeleteTask($taskName,0)
        Demand ($null -eq (LookupTask)); NoRollbackProcess
        $script:taskRegistered=$false; $absent=$true
        OriginalMetadata
        Write-Output 'PASS: PREMUTATION_TASK_DISABLED_QUIESCENT_REMOVED'
    } catch {
        $script:passed=$false; $script:canCleanup=$false
        if ($absent) { Write-Output 'FAIL: PREMUTATION_TASK_ABSENT_ORIGINAL_STATE_UNPROVEN; private backup retained; human review required' }
        elseif ($disabled) { Write-Output 'FAIL: PREMUTATION_TASK_DISABLED_OR_REMOVED_PROOF_INCOMPLETE; private backup retained; human review required' }
        elseif ($knownOwned) { Write-Output 'FAIL: OWN_TASK_MAY_REMAIN_ENABLED; private backup retained; human review required' }
        else { Write-Output 'FAIL: TASK_OWNERSHIP_UNCERTAIN_MAY_REMAIN_ENABLED; no foreign task touched; private backup retained' }
    }
}
function NoRollbackProcess {
    # Zero LIKE rows is not proof when SYSTEM command lines are redacted.
    # Provider-side predicates + ProcessId-only projection never return foreign args.
    $unknown=@(Get-CimInstance Win32_Process -Filter "Name='cmd.exe' AND (CommandLine IS NULL OR CommandLine='')" -Property ProcessId -OperationTimeoutSec 5)
    Demand ($unknown.Count -eq 0)
    $processes=@(Get-CimInstance Win32_Process -Filter ("Name='cmd.exe' AND CommandLine LIKE '%{0}%'" -f $Authorize) -Property ProcessId -OperationTimeoutSec 5)
    Demand ($processes.Count -eq 0)
}
function OriginalMetadata {
    Demand ((Hash $installedExe) -eq $originalHash -and (PinFile $installedExe $true) -eq $installedId)
    Demand ((SddlHash $installedExe) -eq $originalSd -and (SddlHash $installDirectory) -eq $directorySd)
    Demand ((ConfigDigest) -eq $originalConfig -and (TextHash (Run $sc 'sdshow RTrustTunnel' 10000)) -eq $originalScSecurity)
    Demand ((TextHash (Run $sc 'qfailure RTrustTunnel' 10000)) -eq $originalFailures -and
        (TextHash (Run $sc 'qfailureflag RTrustTunnel' 10000)) -eq $originalFailureFlag)
    Demand ((Hash $wintun) -eq $wintunHash -and (PinFile $wintun) -eq $wintunId -and (SddlHash $wintun) -eq $wintunSd)
    Demand ((KeyMetadata) -eq $keyMetadata -and (DnsDigest) -eq $dns)
    $s=Service; Demand ($s.State -eq 'Running'); [void](ServiceProcess $s)
    AbsentState
}
function CleanupFence {
    Demand ($watch.Elapsed.TotalMinutes -lt 20 -and [DateTime]::UtcNow -lt $watchdogUtc.AddMinutes(-3))
    # Disable future launches FIRST. This neither stops nor kills an active cmd.
    [void](Disable-ScheduledTask -TaskName $taskName)
    Demand (-not $registeredCom.Enabled)
    TaskSecurity $registeredCom # Gate removal, not the prior disabling of our owned task.
    $timer=[Diagnostics.Stopwatch]::StartNew()
    while ($registeredCom.GetInstances(0).Count -ne 0) {
        Demand ($timer.Elapsed.TotalSeconds -lt 120 -and $watch.Elapsed.TotalMinutes -lt 20)
        Start-Sleep -Milliseconds 250
    }
    Demand ((Get-ScheduledTask -TaskName $taskName).State -eq 'Disabled')
    NoRollbackProcess
    Start-Sleep -Milliseconds 250
    Demand ($registeredCom.GetInstances(0).Count -eq 0 -and -not $registeredCom.Enabled)
    NoRollbackProcess
    OriginalMetadata
    Demand ($watch.Elapsed.TotalMinutes -lt 20 -and [DateTime]::UtcNow -lt $watchdogUtc.AddMinutes(-3))
}
function ClosePins {
    foreach ($pin in $pins) {
        if (-not [RTrust107Installed]::CloseHandle($pin)) { $script:canCleanup=$false; $script:passed=$false }
    }
    $pins.Clear()
}
function CleanupStage {
    # Only the private nonce leaf. Never traverse/delete the canonical journal.
    $allowed=@('candidate.exe','original.exe','start-test.exe','journal-test.exe','rollback.cmd',
        'original.acl','original-acl.txt','original-id.txt','probe.bin','synth2','probe-id-before.txt',
        'probe-id-after.txt','network-baseline.json','journal-first.state','watchdog.armed',
        'rollback.started','rollback.ok','hash.txt','sc-state.txt','restored-id.txt','restored-acl.txt')
    NoReparse $stage
    foreach ($path in [IO.Directory]::EnumerateFileSystemEntries($stage)) {
        Demand ($allowed -contains [IO.Path]::GetFileName($path)); NoReparse $path
        Demand (([IO.File]::GetAttributes($path) -band [IO.FileAttributes]::Directory) -eq 0)
    }
    foreach ($path in [IO.Directory]::EnumerateFiles($stage)) { [IO.File]::Delete($path) }
    [IO.Directory]::Delete($stage,$false)
}

try {
    $cmd=OsTool 'cmd.exe'; $sc=OsTool 'sc.exe'; $icacls=OsTool 'icacls.exe'; $fsutil=OsTool 'fsutil.exe'
    foreach ($name in @('certutil.exe','fc.exe','findstr.exe','ping.exe')) { [void](OsTool $name) }
    $SourceDirectory=[IO.Path]::GetFullPath($SourceDirectory).TrimEnd('\')
    BuildChain $SourceDirectory $false
    # VerifySourceGit pins these inputs and compares their raw bytes to HEAD blobs,
    # independently of the index stat cache. Use Git-relative forward-slash names.
    $sourceInputs=@('ci/windows-issue107-acceptance.ps1','ci/windows-issue107-rollback.cmd.in',
        'apps/tun/tests/windows_installed_start.rs','crates/journal/tests/windows_installed_journal.rs',
        'apps/tun/src/windows/firewall.rs')
    try { VerifySourceGit }
    catch { $blocked=$true; Write-Output 'BLOCKED: GIT_PROVENANCE_UNPROVEN'; throw 'isolated source verification=false' }
    $templatePath=Join-Path $SourceDirectory 'ci\windows-issue107-rollback.cmd.in'
    $firewall=[IO.File]::ReadAllText((Join-Path $SourceDirectory 'apps\tun\src\windows\firewall.rs'))
    Demand ($firewall.Contains('0xd358e5b4_9891_4b22_b071_d95fef406791') -and $firewall.Contains('0x9b93baf4_7dd4_47b6_8b24_32497ba29261'))
    foreach ($path in @($CandidatePath,$StartTestPath,$JournalTestPath)) { BuildChain $path $true; RequireLoaderProof $path }
    Demand ((Hash $CandidatePath) -eq $CandidateSha256.ToLowerInvariant())
    Demand ((Hash $StartTestPath) -eq $StartTestSha256.ToLowerInvariant())
    Demand ((Hash $JournalTestPath) -eq $JournalTestSha256.ToLowerInvariant())
    QuietUi
    $s=Service
    Demand ($s.StartName -eq 'LocalSystem' -and $s.State -eq 'Running')
    Demand ($s.PathName -match '^"(?<exe>[A-Za-z0-9 :\\._()-]+)" --service (?<sid>S-1-[0-9-]+)$')
    $installedExe=[IO.Path]::GetFullPath($Matches.exe)
    Demand ($Matches.sid -eq $identity.User.Value)
    $installDirectory=[IO.Path]::GetDirectoryName($installedExe)
    $installParent=[IO.Path]::GetDirectoryName($installDirectory)
    foreach ($path in @($installedExe,$installDirectory,$installParent,$systemDirectory)) { [void](SafeLiteral $path) }
    Ancestors $installDirectory; OsProtected $installDirectory; OsProtected $installedExe
    $installedId=PinFile $installedExe $true
    RequireLoaderProof $installedExe
    $originalHash=Hash $installedExe; $originalSd=SddlHash $installedExe; $directorySd=SddlHash $installDirectory
    Demand ($originalHash -eq $OriginalSha256.ToLowerInvariant())
    [void](ServiceProcess $s)
    $originalConfig=ConfigDigest; $originalScSecurity=TextHash (Run $sc 'sdshow RTrustTunnel' 10000)
    $originalFailures=TextHash (Run $sc 'qfailure RTrustTunnel' 10000)
    $originalFailureFlag=TextHash (Run $sc 'qfailureflag RTrustTunnel' 10000)
    $wintun=Join-Path $installDirectory 'wintun.dll'; OsProtected $wintun; $wintunId=PinFile $wintun
    $wintunSd=SddlHash $wintun
    $wintunHash=Hash $wintun; Demand ($wintunHash -eq $WintunSha256.ToLowerInvariant())
    $keyMetadata=KeyMetadata; $dns=DnsDigest
    AbsentState
    Demand (-not [IO.Directory]::Exists((Join-Path $programData 'R-TrustTunnel\logs')))
    Explorer
    $stage=Join-Path $installParent ('RTrustAcceptance-'+$Authorize)
    [void](SafeLiteral $stage); NewPrivateDirectory $stage
    $candidate=Join-Path $stage 'candidate.exe'; $backup=Join-Path $stage 'original.exe'
    $startTest=Join-Path $stage 'start-test.exe'; $journalTest=Join-Path $stage 'journal-test.exe'
    [IO.File]::Copy($CandidatePath,$candidate,$false); [IO.File]::Copy($installedExe,$backup,$false)
    [IO.File]::Copy($StartTestPath,$startTest,$false); [IO.File]::Copy($JournalTestPath,$journalTest,$false)
    foreach ($path in @($candidate,$backup,$startTest,$journalTest)) { PrivateAcl $path $false; [void](PinFile $path) }
    Demand ((Hash $backup) -eq $originalHash -and (Hash $candidate) -eq $CandidateSha256.ToLowerInvariant())
    Demand ((Hash $startTest) -eq $StartTestSha256.ToLowerInvariant() -and (Hash $journalTest) -eq $JournalTestSha256.ToLowerInvariant())
    $env:RTRUST_INSTALLED_ACCEPTANCE=$Authorize; $env:RTRUST_INSTALLED_STAGE=$stage
    Native $journalTest $JournalTestSha256 'installed_explorer_preflight' @('PASS: GENUINE_EXPLORER_TOKEN_AND_ACTUAL_THREAD') $false
    Snapshot $true; Start-Sleep -Seconds 10; Snapshot $false
    Demand ((DnsDigest) -eq $dns -and (KeyMetadata) -eq $keyMetadata)
    $probe=Join-Path $stage 'probe.bin'; $synth=Join-Path $stage 'synth2'
    [IO.File]::WriteAllText($probe,'synthetic-one'); [IO.File]::WriteAllText($synth,'synthetic-two')
    # A distinct explicit SD is synthetic-only; this never changes installed ACLs.
    $probeAcl=[Security.AccessControl.FileSecurity]::new()
    $probeAcl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;;FA;;;BA)(A;;0x120089;;;SY)')
    Set-Acl -LiteralPath $probe -AclObject $probeAcl
    $probeSd=SddlHash $probe
    [void](PinFile $probe $true) # Same GENERIC_READ, share READ|WRITE/no DELETE as installedExe.
    RawCapture $fsutil ('file queryfileid "{0}"' -f $probe) (Join-Path $stage 'probe-id-before.txt')
    [void](Run $cmd ('/d /c copy /b /y "{0}" "{1}"' -f $synth,$probe))
    RawCapture $fsutil ('file queryfileid "{0}"' -f $probe) (Join-Path $stage 'probe-id-after.txt')
    Demand ((Hash $probe) -eq (Hash $synth))
    Demand ((SddlHash $probe) -eq $probeSd)
    Demand (([IO.File]::ReadAllText((Join-Path $stage 'probe-id-before.txt'))) -ceq
        ([IO.File]::ReadAllText((Join-Path $stage 'probe-id-after.txt'))))
    Write-Output 'PASS: COPY_PRESERVES_SD_ID'
    RawCapture $fsutil ('file queryfileid "{0}"' -f $installedExe) (Join-Path $stage 'original-id.txt')
    RawCapture $icacls ('"{0}"' -f $installedExe) (Join-Path $stage 'original-acl.txt')
    [void](Run $icacls ('"{0}" /save "{1}"' -f $installedExe,(Join-Path $stage 'original.acl')))
    Demand (([IO.File]::ReadAllLines((Join-Path $stage 'original.acl'),[Text.Encoding]::Unicode))[0] -eq [IO.Path]::GetFileName($installedExe))
    $rollback=Join-Path $stage 'rollback.cmd'
    $rendered=[IO.File]::ReadAllText($templatePath)
    $values=@{ SYSTEM32=$systemDirectory; STAGE=$stage; NONCE=$Authorize; INSTALL_DIR=$installDirectory;
        BACKUP=$backup; INSTALLED_EXE=$installedExe; ORIGINAL_SHA256=$originalHash }
    foreach ($key in $values.Keys) { [void](SafeLiteral $values[$key]); $rendered=$rendered.Replace('@'+$key+'@',$values[$key]) }
    Demand ($rendered -notmatch '@[A-Z_]+@')
    [IO.File]::WriteAllText($rollback,$rendered.Replace("`r`n","`n").Replace("`n","`r`n"),[Text.Encoding]::ASCII)
    PrivateAcl $rollback $false; [void](PinFile $rollback); $rollbackHash=Hash $rollback
    Write-Output 'PASS: PREFLIGHT_IDLE_TWO_SAMPLES'
    if (-not $ExecuteSwap) { Write-Output 'NOT RUN: installed swap; preflight only'; exit 1 }
    # Backup and a proven SYSTEM-owned ARMED receipt precede the first service stop.
    [IO.File]::WriteAllText((Join-Path $stage 'armed.request'),$Authorize,[Text.Encoding]::ASCII)
    $watchdogUtc=[DateTime]::UtcNow.AddMinutes(25)
    $taskName='RTrustAcceptance-'+$Authorize
    $scheduler=New-Object -ComObject 'Schedule.Service'; $scheduler.Connect()
    $taskFolder=$scheduler.GetFolder('\')
    Demand ($null -eq (LookupTask))
    NoRollbackProcess
    $taskArguments='/d /c ""{0}""' -f $rollback
    $boundary=$watchdogUtc.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'",[Globalization.CultureInfo]::InvariantCulture)
    # RegisterTask supplies the initial protected SD atomically. Never briefly
    # register a SYSTEM task whose default creator ACE might admit a medium user.
    $xml=@"
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><TimeTrigger><StartBoundary>$boundary</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers>
  <Principals><Principal id="Rollback"><UserId>$systemSid</UserId><LogonType>ServiceAccount</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><Enabled>true</Enabled><ExecutionTimeLimit>PT4M</ExecutionTimeLimit></Settings>
  <Actions Context="Rollback"><Exec><Command>$cmd</Command><Arguments>$taskArguments</Arguments><WorkingDirectory>$systemDirectory</WorkingDirectory></Exec></Actions>
</Task>
"@
    $taskSddl='O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'
    # TASK_CREATE | TASK_DONT_ADD_PRINCIPAL_ACE; TASK_LOGON_SERVICE_ACCOUNT.
    $taskRegistrationAttempted=$true
    $registeredCom=$taskFolder.RegisterTask($taskName,$xml,18,$systemSid,$null,5,$taskSddl)
    $taskRegistered=$true
    TaskSecurity $registeredCom
    $registered=Get-ScheduledTask -TaskName $taskName
    Demand ($registered.Principal.UserId -eq $systemSid -and $registered.Principal.LogonType -eq 'ServiceAccount')
    Demand ($registered.Principal.RunLevel -eq 'Highest' -and $registered.Settings.StartWhenAvailable)
    Demand ($registered.Settings.ExecutionTimeLimit -eq 'PT4M' -and $registered.Settings.MultipleInstances -eq 'IgnoreNew')
    Demand (@($registered.Actions).Count -eq 1 -and $registered.Actions[0].Execute -ceq $cmd -and $registered.Actions[0].Arguments -ceq $taskArguments)
    Demand (@($registered.Triggers).Count -eq 1 -and $registered.Triggers[0].CimClass.CimClassName -eq 'MSFT_TaskTimeTrigger')
    $next=(Get-ScheduledTaskInfo -TaskName $taskName).NextRunTime.ToUniversalTime()
    Demand ([Math]::Abs(($next-$watchdogUtc).TotalSeconds) -le 3)
    TaskRun 'watchdog.armed' 30
    $armed=$true; $watch.Start()
    Write-Output 'PASS: WATCHDOG_ARMED'
    Demand ($registeredCom.GetInstances(0).Count -eq 0)
    NoRollbackProcess
    BeforeMutation
    OriginalMetadata
    Snapshot $false $true
    CandidateStop
    BeforeMutation
    Demand ((Hash $candidate) -eq $CandidateSha256.ToLowerInvariant())
    $swapped=$true
    [void](Run $cmd ('/d /c copy /b /y "{0}" "{1}"' -f $candidate,$installedExe))
    Demand ((SddlHash $installedExe) -eq $originalSd -and (SddlHash $installDirectory) -eq $directorySd)
    $p1=CandidateStart; $env:RTRUST_INSTALLED_PID1=[string]$p1; $env:RTRUST_INSTALLED_PID2='0'
    Snapshot $false $true
    $env:RTRUST_INSTALLED_TRIGGER=[string][DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    Native $startTest $StartTestSha256 'start_validation' @('PASS: B_CAPS_MATCH','PASS: B_REPLY_ERROR','PASS: B_MESSAGE_MATCH','PASS: B_NO_OWNER','PASS: B_NO_OS_MUTATION')
    $env:RTRUST_INSTALLED_PHASE='first'
    Native $journalTest $JournalTestSha256 'installed_journal' @('PASS: C_FILTERED_READ_GRANTED','PASS: C_FILTERED_WRITE_DENIED','PASS: C_GENUINE_MEDIUM_REAL_OPENS','PASS: C_CANARY_ABSENT','PASS: INSTALLED_JOURNAL_COMPLETE')
    CandidateStop; $p2=CandidateStart; Demand ($p2 -ne $p1); $env:RTRUST_INSTALLED_PID2=[string]$p2
    $env:RTRUST_INSTALLED_PHASE='persisted'
    Native $journalTest $JournalTestSha256 'installed_journal' @('PASS: C_RESTART_PERSISTED','PASS: C_GENUINE_MEDIUM_REAL_OPENS','PASS: INSTALLED_JOURNAL_COMPLETE')
    Native $startTest $StartTestSha256 'start_validation' @('PASS: B_CAPS_MATCH','PASS: B_REPLY_ERROR','PASS: B_MESSAGE_MATCH','PASS: B_NO_OWNER','PASS: B_NO_OS_MUTATION')
    $env:RTRUST_INSTALLED_PHASE='appended'
    Native $journalTest $JournalTestSha256 'installed_journal' @('PASS: C_APPEND_AFTER_RESTART','PASS: C_GENUINE_MEDIUM_REAL_OPENS','PASS: C_CANARY_ABSENT','PASS: INSTALLED_JOURNAL_COMPLETE')
    Demand ((DnsDigest) -eq $dns -and (KeyMetadata) -eq $keyMetadata)
    $passed=$true
} catch {
    $passed=$false
    if ($blocked) { Write-Output 'BLOCKED: installed acceptance' }
    else { Write-Output 'FAIL: installed acceptance (details suppressed)' }
} finally {
    if ($taskRegistrationAttempted -and -not $mutationStarted) {
        CleanupBeforeMutation
    }
    if ($armed -and $mutationStarted) {
        try {
            # Never stop a running rollback, even if a probe failed or the main budget expired.
            if (-not [IO.File]::Exists((Join-Path $stage 'rollback.started'))) { TaskRun 'rollback.ok' 120 }
            else {
                $timer=[Diagnostics.Stopwatch]::StartNew()
                while ((Get-ScheduledTask -TaskName $taskName).State -eq 'Running') {
                    Demand ($timer.Elapsed.TotalSeconds -lt 120); Start-Sleep -Milliseconds 250
                }
                Demand ((Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult -eq 0)
                SystemReceipt 'rollback.ok'
            }
            OriginalMetadata
            Snapshot $false
            $restored=$true
            Write-Output 'PASS: ORIGINAL_RESTORED_INDEPENDENTLY'
        } catch {
            $restored=$false; $passed=$false; $canCleanup=$false
            Write-Output 'FAIL: RESTORE_HUMAN_REQUIRED; private backup and watchdog retained'
        }
    }
    # A failed/BLOCKED test is not permission to leave a stale enabled watchdog.
    if ($restored -and $canCleanup) {
        try {
            CleanupFence
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            Demand ($null -eq (LookupTask))
            $taskRegistered=$false
            # Unregistration is not termination. Keep backup on any uncertainty,
            # including a clock jump, queued instance or a surviving SYSTEM cmd.
            NoRollbackProcess
            Start-Sleep -Milliseconds 250
            NoRollbackProcess
            Demand ($watch.Elapsed.TotalMinutes -lt 20 -and [DateTime]::UtcNow -lt $watchdogUtc.AddMinutes(-3))
            ClosePins
            Demand $canCleanup
            CleanupStage
            Write-Output 'PASS: CANONICAL_JOURNAL_LEFT_INTACT'
            if ($passed) { Write-Output 'PASS: INSTALLED_ACCEPTANCE_COMPLETE' }
            else { Write-Output 'PASS: RESTORED_FAILURE_PATH_CLEANUP_COMPLETE; overall result remains FAIL/BLOCKED' }
        } catch { $passed=$false; Write-Output 'FAIL: private acceptance cleanup (details suppressed)' }
    } elseif ($stage) {
        Write-Output 'NOT RUN: cleanup; private stage retained; canonical journal untouched'
    }
    if ($taskRegistered) {
        $passed=$false
        try {
            if ($registeredCom.Enabled) { Write-Output 'FAIL: WATCHDOG_RETAINED_ENABLED; future SYSTEM action may restart or overwrite original; private backup retained; human review required' }
            else { Write-Output 'FAIL: WATCHDOG_RETAINED_DISABLED; private backup retained; human review required' }
        } catch { Write-Output 'FAIL: WATCHDOG_RETAINED_STATE_UNPROVEN; may remain enabled; private backup retained; human review required' }
    }
    ClosePins
    Write-Output 'NOT RUN: compiler bootstrap cleanup; protected temporary files retained'
    Write-Output 'NOT RUN: pre-swap canonical root ACL-shape gate (L2 deferred); no ACL repair'
    Write-Output 'NOT RUN: human publish/self-mode fallback (deferred); genuine Explorer proof is mandatory before service mutation'
    Write-Output 'NOT RUN: kill switch, DNS/IPv6 leaks, reboot; snapshots cannot exclude transient changes'
}
if (-not $passed) { exit 1 }
