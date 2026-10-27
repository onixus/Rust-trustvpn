# Manual synthetic native acceptance, elevated x64 Admin, NEVER SYSTEM.
# Explicit human temporary-SYSTEM-task consent, immutable reviewed HEAD and fresh
# protected-build attestation are prerequisites. No service/package/network changes.
# REQUIRED BEFORE LAUNCH: independently verified trusted NATIVE parent supplies an
# explicit clean environment BEFORE CLR initialization, then trusted x64 host with
# -NoProfile -NonInteractive -File <canonical source script>. Detection below is
# after the fact, NOT proof of clean CLR startup. Runtime remains BLOCKED without it.
# Independently verify trusted OS/COM activation and AppLocker/WDAC allowance too;
# a script cannot prove absence of per-user startup/redirection races after launch.
# Canonical ProgramData journal is NEVER touched by this synthetic harness.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ArtifactPath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$ExpectedRevision,
    [Parameter(Mandatory=$true)][string]$SourceDirectory,
    [Parameter(Mandatory=$true)][string]$ProtectedBuildRoot,
    [Parameter(Mandatory=$true)][string]$GitPath
)
# Parser/parameter-binding errors occur before this trap: caller must suppress
# raw stderr and perform a separate parser gate before invoking this script.
trap { [Console]::Out.WriteLine('FAIL: native launcher runtime (details suppressed)'); exit 1 }
Microsoft.PowerShell.Core\Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Demand([bool]$Condition) { if (-not $Condition) { throw 'native acceptance assertion=false' } }
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
$launcherSource=[IO.Path]::GetFullPath([IO.Path]::Combine([IO.Path]::GetFullPath($SourceDirectory),'ci\issue107_windows_native.ps1'))
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
$guid=[Guid]::NewGuid().ToString('N')
$bootstrap= $ProtectedBuildRoot+'\RTrustCompiler-'+$guid
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
public static class RTrust107Native {
    [StructLayout(LayoutKind.Sequential)] public struct SA { public int Length; public IntPtr Descriptor; public int Inherit; }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern bool CreateDirectoryW(string path, ref SA attributes);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] public static extern uint GetSystemDirectoryW(StringBuilder buffer, uint size);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] public static extern uint GetWindowsDirectoryW(StringBuilder buffer, uint size);

    [StructLayout(LayoutKind.Sequential)] public struct INFO {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [StructLayout(LayoutKind.Sequential)] struct US { public ushort Length, Maximum; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)] struct OA {
        public int Length; public IntPtr Root, Name; public uint Attributes; public IntPtr SD, QoS;
    }
    [StructLayout(LayoutKind.Sequential)] struct IOS { public IntPtr Status; public UIntPtr Information; }
    [StructLayout(LayoutKind.Sequential)] struct DISPOSITION { public int Delete; }
    public sealed class ENTRY { public string Name; public ulong Id; public uint Attributes; }
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetFileInformationByHandle(IntPtr h, out INFO info);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] public static extern uint GetDriveTypeW(string root);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)] static extern uint GetFileAttributesW(string path);
    public static void Absent(string path) {
        uint attributes=GetFileAttributesW(path); int error=Marshal.GetLastWin32Error();
        Check(attributes==UInt32.MaxValue && error==2); // NOT access denied/delete-pending/path-missing.
    }
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandleEx(IntPtr h, int kind, IntPtr buffer, uint size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetFileInformationByHandle(IntPtr h, int kind, ref DISPOSITION data, uint size);
    [DllImport("ntdll.dll")] static extern int NtCreateFile(out IntPtr h, uint access, ref OA oa, out IOS io, IntPtr allocation,
        uint attributes, uint share, uint disposition, uint options, IntPtr ea, uint eaLength);
    static void Check(bool value) { if (!value) throw new InvalidOperationException("native handle proof=false"); }
    public static INFO Facts(IntPtr h) { INFO value; Check(GetFileInformationByHandle(h,out value)); return value; }
    public static ulong Id(INFO value) { return ((ulong)value.IndexHigh << 32) | value.IndexLow; }
    public static IntPtr OwnRoot(string path, bool directory) {
        // DELETE access is ONLY for own stage objects, never provenance pins.
        IntPtr h=CreateFileW(path,directory ? 0x130081u : 0x80130080u,1,IntPtr.Zero,3,
            directory ? 0x02200000u : 0x00200000u,IntPtr.Zero);
        Check(h!=new IntPtr(-1)); return h;
    }
    public static IntPtr Relative(IntPtr parent, string name, bool directory) {
        Check(name.Length>0 && name.Length<=255);
        foreach (char c in name) Check((c>='A' && c<='Z') || (c>='a' && c<='z') ||
            (c>='0' && c<='9') || c=='.' || c=='_' || c=='-');
        Check(name!="." && name!="..");
        IntPtr text=Marshal.StringToHGlobalUni(name), descriptor=IntPtr.Zero;
        try {
            US u=new US(); u.Length=checked((ushort)(name.Length*2)); u.Maximum=checked((ushort)(u.Length+2)); u.Buffer=text;
            descriptor=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(US))); Marshal.StructureToPtr(u,descriptor,false);
            OA oa=new OA(); oa.Length=Marshal.SizeOf(typeof(OA)); oa.Root=parent; oa.Name=descriptor; oa.Attributes=0x40;
            IOS io; IntPtr h;
            // SINGLE relative basename, FILE_OPEN, OPEN_REPARSE_POINT and typed.
            // SYNCHRONIZE + FILE_SYNCHRONOUS_IO_NONALERT, no backup privilege.
            int status=NtCreateFile(out h,directory ? 0x130081u : 0x130080u,ref oa,out io,IntPtr.Zero,
                0,1,1,0x00200020u | (directory ? 1u : 0x40u),IntPtr.Zero,0);
            Check(status>=0 && h!=IntPtr.Zero && h!=new IntPtr(-1)); return h;
        } finally { if (descriptor!=IntPtr.Zero) Marshal.FreeHGlobal(descriptor); Marshal.FreeHGlobal(text); }
    }
    public static ENTRY[] Entries(IntPtr directory) {
        const int size=65536; IntPtr buffer=Marshal.AllocHGlobal(size);
        var entries=new System.Collections.Generic.List<ENTRY>();
        try {
            // FILE_ID_BOTH_DIR_INFO / restart. No pathname enumeration or DFS.
            for (int page=0; page<4; page++) {
                if (!GetFileInformationByHandleEx(directory,page==0 ? 11 : 10,buffer,size)) {
                    Check(Marshal.GetLastWin32Error()==18); return entries.ToArray();
                }
                int offset=0;
                for (int record=0; record<512; record++) {
                    Check(offset>=0 && offset<=size-104);
                    IntPtr item=IntPtr.Add(buffer,offset);
                    uint next=unchecked((uint)Marshal.ReadInt32(item,0));
                    uint length=unchecked((uint)Marshal.ReadInt32(item,60));
                    Check(length>0 && length<=510 && (length & 1)==0 && length<=(uint)(size-offset-104));
                    string name=Marshal.PtrToStringUni(IntPtr.Add(item,104),(int)length/2);
                    if (name!="." && name!="..") {
                        Check(entries.Count<64); ENTRY entry=new ENTRY(); entry.Name=name;
                        entry.Attributes=unchecked((uint)Marshal.ReadInt32(item,56));
                        entry.Id=unchecked((ulong)Marshal.ReadInt64(item,96)); entries.Add(entry);
                    }
                    if (next==0) break;
                    Check(next>=104+length && (next & 7)==0 && next<=(uint)(size-offset-104));
                    offset+=checked((int)next); Check(record<511);
                }
            }
            throw new InvalidOperationException("bounded native enumeration exhausted");
        } finally { Marshal.FreeHGlobal(buffer); }
    }
    public static string HashOwned(IntPtr h) {
        // FileShare.Read pathname reopens conflict with existing DELETE access.
        using (var safe=new Microsoft.Win32.SafeHandles.SafeFileHandle(h,false))
        using (var stream=new System.IO.FileStream(safe,System.IO.FileAccess.Read))
        using (var sha=System.Security.Cryptography.SHA256.Create()) {
            long position=stream.Position;
            try { stream.Position=0; return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-",""); }
            finally { stream.Position=position; }
        }
    }
    public static void Unlink(IntPtr h) {
        DISPOSITION data=new DISPOSITION(); data.Delete=1;
        Check(SetFileInformationByHandle(h,4,ref data,4));
    }
    public static async System.Threading.Tasks.Task<string> ReadBounded(System.IO.StreamReader reader, int limit) {
        Check(limit>0 && limit<=8388608);
        var text=new System.Text.StringBuilder(); char[] buffer=new char[4096];
        while (true) {
            int count=await reader.ReadAsync(buffer,0,buffer.Length).ConfigureAwait(false);
            if (count==0) return text.ToString();
            Check(text.Length<=limit-count); text.Append(buffer,0,count);
        }
    }
}
'@

$pins=[Collections.Generic.List[IntPtr]]::new()
$owned=[Collections.Generic.List[IntPtr]]::new()
$ownedByRelative=[Collections.Generic.Dictionary[string,IntPtr]]::new([StringComparer]::Ordinal)
$stage=$null; $stageCreated=$false; $stagePin=$null; $fixturePin=$null; $taskName=$null; $taskRegistered=$false
$taskRegistrationAttempted=$false; $systemMatrixMayHaveRun=$false; $registeredCom=$null
$taskFolder=$null; $scheduler=$null; $canCleanup=$true; $failed=$false; $blocked=$false; $exe=$null
$watch=[Diagnostics.Stopwatch]::StartNew()
function NoReparse([string]$Path) {
    Demand (([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::ReparsePoint) -eq 0)
}
function PinDirectory([string]$Path) {
    $handle=[RTrust107Native]::CreateFileW($Path,0x20080,3,[IntPtr]::Zero,3,0x02200000,[IntPtr]::Zero)
    Demand ($handle -ne [IntPtr]::new(-1))
    $pins.Add($handle); NoReparse $Path
}
function RuntimePin([string]$Path) {
    # Metadata-only references do not participate in data/delete share checks.
    # The checked SY/BA ACLs, not these references, exclude foreign renames.
    $handle=[RTrust107Native]::CreateFileW($Path,0x20080,3,[IntPtr]::Zero,3,0x02200000,[IntPtr]::Zero)
    Demand ($handle -ne [IntPtr]::new(-1) -and $handle -ne [IntPtr]::Zero)
    try {
        $facts=[RTrust107Native]::Facts($handle)
        Demand (($facts.Attributes -band 0x410) -eq 0x10)
        return [PSCustomObject]@{ Handle=$handle; Facts=$facts }
    } catch {
        $script:canCleanup=$false
        Demand ([RTrust107Native]::CloseHandle($handle))
        throw 'runtime directory reference=false'
    }
}
function PinFile([string]$Path,[bool]$Writable=$false) {
    $share=if ($Writable) { 3 } else { 1 }
    $handle=[RTrust107Native]::CreateFileW($Path,0x80020080,$share,[IntPtr]::Zero,3,0x00200000,[IntPtr]::Zero)
    Demand ($handle -ne [IntPtr]::new(-1))
    $pins.Add($handle)
    $facts=[RTrust107Native+INFO]::new()
    Demand ([RTrust107Native]::GetFileInformationByHandle($handle,[ref]$facts))
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
    Demand ($drive -match '^[A-Za-z]:\\$' -and [RTrust107Native]::GetDriveTypeW($drive) -eq 3)
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
function NewPrivateDirectory([string]$Path,[bool]$OwnCleanup=$false) {
    $security=[Security.AccessControl.DirectorySecurity]::new()
    $security.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    $bytes=$security.GetSecurityDescriptorBinaryForm()
    $pin=[Runtime.InteropServices.GCHandle]::Alloc($bytes,[Runtime.InteropServices.GCHandleType]::Pinned)
    try {
        $attributes=[RTrust107Native+SA]::new()
        $attributes.Length=[Runtime.InteropServices.Marshal]::SizeOf($attributes)
        $attributes.Descriptor=$pin.AddrOfPinnedObject()
        Demand ([RTrust107Native]::CreateDirectoryW($Path,[ref]$attributes))
    } finally { $pin.Free() }
    $runtimePin=$null
    try {
        if ($OwnCleanup) {
            $runtimePin=RuntimePin $Path
            PrivateAcl $Path $true; return $runtimePin
        }
        PinDirectory $Path; PrivateAcl $Path $true
    }
    catch {
        $script:canCleanup=$false
        if ($null -ne $runtimePin) {
            Demand ([RTrust107Native]::CloseHandle($runtimePin.Handle))
            $runtimePin.Handle=[IntPtr]::Zero
        }
        throw 'protected stage readback=false'
    }
}
function Imports([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    Demand ($bytes.Length -gt 256)
    function U16([int]$Offset) { Demand ($Offset -ge 0 -and $Offset+2 -le $bytes.Length); [BitConverter]::ToUInt16($bytes,$Offset) }
    function U32([int]$Offset) { Demand ($Offset -ge 0 -and $Offset+4 -le $bytes.Length); [BitConverter]::ToUInt32($bytes,$Offset) }
    Demand ((U16 0) -eq 0x5a4d)
    $pe = [int](U32 0x3c)
    Demand ((U32 $pe) -eq 0x4550)
    $sections = U16 ($pe+6)
    $optional = $pe+24
    Demand ((U16 $optional) -eq 0x20b) # PE32+ only; do not guess another layout.
    Demand ((U32 ($optional+108)) -ge 14)
    Demand ((U32 ($optional+112+13*8)) -eq 0) # Refuse unvalidated delay-load imports.
    $sectionTable = $optional+(U16 ($pe+20))
    function Offset([uint32]$Rva) {
        if ($Rva -lt (U32 ($optional+60))) { return [int]$Rva }
        for ($i=0; $i -lt $sections; $i++) {
            $section = $sectionTable+$i*40
            $start = U32 ($section+12); $rawSize = U32 ($section+16)
            if ($Rva -ge $start -and [uint64]$Rva -lt [uint64]$start+$rawSize) {
                return [int]((U32 ($section+20))+$Rva-$start)
            }
        }
        throw 'unmapped PE import=false'
    }
    $rva = U32 ($optional+120)
    Demand ($rva -ne 0)
    $position = Offset $rva
    $names = [Collections.Generic.List[string]]::new()
    for ($i=0; $i -lt 256; $i++) {
        $item = $position+$i*20
        $name = U32 ($item+12)
        if ($name -eq 0) { return $names.ToArray() }
        $start = Offset $name; $end=$start
        while ($end -lt $bytes.Length -and $bytes[$end] -ne 0 -and $end-$start -lt 260) { $end++ }
        Demand ($end -lt $bytes.Length -and $bytes[$end] -eq 0)
        $text = [Text.Encoding]::ASCII.GetString($bytes,$start,$end-$start).ToLowerInvariant()
        Demand ($text -match '^[a-z0-9_-]+\.dll$')
        $names.Add($text)
    }
    throw 'PE import bound=false'
}
function LoaderProof([string]$Executable) {
    OsProtected $systemDirectory
    OsProtected $windowsDirectory
    $known = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $registry = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs'
    foreach ($property in $registry.PSObject.Properties) {
        if ($property.Value -is [string] -and $property.Value -match '^[a-zA-Z0-9_-]+\.dll$') { [void]$known.Add($property.Value) }
    }
    Demand ($known.Count -gt 0)
    $pending = [Collections.Generic.Queue[string]]::new()
    foreach ($name in @(Imports $Executable)) { $pending.Enqueue($name) }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    while ($pending.Count -gt 0) {
        $name=$pending.Dequeue()
        if (-not $seen.Add($name)) { continue }
        Demand ($seen.Count -le 256)
        if ($known.Contains($name)) { continue }
        # A name pattern is NOT OS API-set membership. No regex exemption:
        # logical contracts without a verified physical System32 image fail closed.
        # This deliberately may block a valid artifact pending separate OS mapping proof.
        # E.g. vcruntime is NOT blindly declared a KnownDLL. Resolve only a
        # Microsoft-signed, OS-owned, non-user-writable System32 binary and its imports.
        $dll = Join-Path $systemDirectory $name
        OsProtected $dll
        $signature = Get-AuthenticodeSignature -LiteralPath $dll
        Demand ($signature.Status -eq [Management.Automation.SignatureStatus]::Valid)
        Demand ($signature.SignerCertificate.Subject -match 'O=Microsoft Corporation(?:,|$)')
        foreach ($dependency in @(Imports $dll)) { $pending.Enqueue($dependency) }
    }
    Write-Output 'PASS: loader imports verified; no adjacent DLLs or user PATH'
}
function RequireLoaderProof([string]$Path) {
    try { LoaderProof $Path }
    catch { $script:blocked=$true; Write-Output 'BLOCKED: LOADER_POLICY_UNPROVEN'; throw 'loader proof unavailable=false' }
}
function Evidence([string]$Text,[string[]]$Markers) {
    Demand ($Text -match 'running 1 test')
    Demand ($Text -match 'test result: ok\. 1 passed; 0 failed; 0 ignored;')
    Demand ($Text -notmatch 'NOT RUN:')
    foreach ($marker in $Markers) { Demand ($Text.Contains($marker)) }
}
function SafeLiteral([string]$Value) { Demand ($Value -match '^[A-Za-z0-9 :\\._()-]+$'); return $Value }
function Run([string]$Executable,[string]$Arguments,[int]$Milliseconds=40000,[bool]$AllowFailure=$false,[hashtable]$ExtraEnvironment=@{},[int]$OutputLimit=8388608) {
    $info=[Diagnostics.ProcessStartInfo]::new()
    $info.FileName=$Executable; $info.Arguments=$Arguments; $info.WorkingDirectory=$bootstrap
    $info.UseShellExecute=$false; $info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true; $info.RedirectStandardError=$true
    $info.EnvironmentVariables.Clear()
    foreach ($key in $cleanEnvironment.Keys) { $info.EnvironmentVariables[$key]=[string]$cleanEnvironment[$key] }
    foreach ($key in $ExtraEnvironment.Keys) { $info.EnvironmentVariables[$key]=[string]$ExtraEnvironment[$key] }
    $p=[Diagnostics.Process]::new(); $p.StartInfo=$info
    try {
        Demand ($p.Start()); $stdout=[RTrust107Native]::ReadBounded($p.StandardOutput,$OutputLimit); $stderr=[RTrust107Native]::ReadBounded($p.StandardError,$OutputLimit)
        if (-not $p.WaitForExit($Milliseconds)) {
            try { $p.Kill(); Demand ($p.WaitForExit(10000)) } catch { $script:canCleanup=$false }
            Demand $false
        }
        Demand $p.HasExited
        # A child retaining inherited pipes cannot turn process exit into an
        # unbounded GetResult wait; both captures are character-count/time bounded.
        Demand ($stdout.Wait(5000) -and $stderr.Wait(5000))
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

function PinTrustedTree([string]$Root,[int]$Limit) {
    Ancestors $Root
    $queue=[Collections.Generic.Queue[string]]::new(); $queue.Enqueue($Root); $count=0
    while ($queue.Count -gt 0) {
        $directory=$queue.Dequeue(); PinDirectory $directory; OsProtected $directory
        foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($directory)) {
            $count++; Demand ($count -le $Limit); OsProtected $entry
            if (([IO.File]::GetAttributes($entry) -band [IO.FileAttributes]::Directory) -ne 0) { $queue.Enqueue($entry) }
            else { [void](PinFile $entry) }
        }
    }
}
function LookupTask {
    try { return $taskFolder.GetTask($taskName) }
    catch {
        # ONLY HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) establishes absence.
        $hr=$_.Exception.HResult
        if ($_.Exception.InnerException) { $hr=$_.Exception.InnerException.HResult }
        if ($hr -eq -2147024894) { return $null }
        throw 'native task lookup unproven=false'
    }
}
function TaskSecurity($Task) {
    $sd=[Security.AccessControl.RawSecurityDescriptor]::new($Task.GetSecurityDescriptor(7))
    Demand ($sd.Owner.Value -eq $adminSid -and $sd.Group.Value -eq $adminSid)
    Demand (($sd.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -ne 0)
    Demand ($null -eq $sd.SystemAcl -and $sd.DiscretionaryAcl.Count -eq 2)
    foreach ($sid in @($systemSid,$adminSid)) {
        $count=0
        foreach ($ace in $sd.DiscretionaryAcl) {
            if ($ace.SecurityIdentifier.Value -eq $sid) {
                Demand ($ace -is [Security.AccessControl.CommonAce])
                Demand ($ace.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessAllowed -and $ace.AceFlags -eq 0 -and $ace.AccessMask -eq 0x1f01ff)
                $count++
            }
        }
        Demand ($count -eq 1)
    }
}
function TaskIdentity($Task) {
    Demand ($null -ne $Task -and $Task.Name -ceq $taskName -and $Task.Path -ceq ('\'+$taskName))
    $definition=$Task.Definition
    Demand ($definition.RegistrationInfo.Author -ceq $taskName)
    Demand ($definition.Principal.UserId -in @($systemSid,'SYSTEM','NT AUTHORITY\SYSTEM'))
    Demand ($definition.Principal.LogonType -eq 5 -and $definition.Principal.RunLevel -eq 1)
    Demand ($definition.Triggers.Count -eq 0 -and $definition.Actions.Count -eq 1)
    $action=$definition.Actions.Item(1)
    Demand ($action.Type -eq 0 -and $action.Path -ieq ($systemDirectory+'\cmd.exe') -and $action.WorkingDirectory -ieq $stage)
    $valid=$false
    foreach ($phase in @('system_matrix','system_cleanup')) {
        if ($action.Arguments -ceq ('/d /s /c ""'+(Join-Path $stage ($phase+'.cmd'))+'""')) { $valid=$true }
    }
    Demand $valid
    Demand ($definition.Settings.MultipleInstances -eq 2 -and $definition.Settings.AllowDemandStart)
    Demand ($definition.Settings.ExecutionTimeLimit -in @('PT600S','PT120S','PT10M','PT2M'))
}
function NoNativeProcesses {
    # Server-side projection ONLY: no raw foreign command lines materialized/logged.
    $hidden=@(Get-CimInstance -Query "SELECT ProcessId FROM Win32_Process WHERE Name='cmd.exe' AND (CommandLine IS NULL OR CommandLine='')" -OperationTimeoutSec 5)
    Demand ($hidden.Count -eq 0)
    $commands=@(Get-CimInstance -Query ("SELECT ProcessId FROM Win32_Process WHERE Name='cmd.exe' AND CommandLine LIKE '%"+$taskName+"%'") -OperationTimeoutSec 5)
    Demand ($commands.Count -eq 0)
    $native=@(Get-CimInstance -Query ("SELECT ProcessId FROM Win32_Process WHERE Name='"+[IO.Path]::GetFileName($exe)+"'") -OperationTimeoutSec 5)
    Demand ($native.Count -eq 0)
}
function Quiescent($Task) {
    TaskIdentity $Task; TaskSecurity $Task
    Demand (-not $Task.Enabled -and $Task.State -in @(1,3))
    Demand ($Task.GetInstances(0).Count -eq 0)
    NoNativeProcesses
}
function StopOwnedTask {
    $task=LookupTask
    if ($null -eq $task) {
        NoNativeProcesses; Start-Sleep -Milliseconds 250; NoNativeProcesses
        $script:taskRegistered=$false
        return $null
    }
    TaskIdentity $task
    # Bind exact nonce/action/principal, then disable BEFORE SD checking: malformed
    # SD is uncertainty, not permission to leave a known own task enabled.
    $task.Enabled=$false
    $fresh=LookupTask; TaskIdentity $fresh; Demand (-not $fresh.Enabled)
    TaskSecurity $fresh
    try { $task.Stop(0) }
    catch {
        # TASK_NOT_RUNNING is allowed ONLY with subsequent fresh instances/state.
        $hr=$_.Exception.HResult
        if ($_.Exception.InnerException) { $hr=$_.Exception.InnerException.HResult }
        Demand ($hr -eq -2147216629)
    }
    $timer=[Diagnostics.Stopwatch]::StartNew()
    while ($true) {
        $task=LookupTask; TaskIdentity $task; TaskSecurity $task
        Demand (-not $task.Enabled)
        if ($task.State -in @(1,3) -and $task.GetInstances(0).Count -eq 0) { break }
        Demand ($timer.Elapsed.TotalSeconds -lt 15); Start-Sleep -Milliseconds 100
    }
    Quiescent $task; Start-Sleep -Milliseconds 250; Quiescent (LookupTask)
    return $task
}
function OwnedExeHash {
    Demand ($ownedByRelative.ContainsKey([IO.Path]::GetFileName($exe)))
    $handle=$ownedByRelative[[IO.Path]::GetFileName($exe)]
    $facts=[RTrust107Native]::Facts($handle)
    Demand (($facts.Attributes -band 0x410) -eq 0 -and $facts.Links -eq 1)
    Demand ([RTrust107Native]::HashOwned($handle) -ieq $ExpectedSha256)
}
function PhaseCommand([string]$Filter) {
    $path=Join-Path $stage ($Filter+'.cmd')
    Demand (-not [IO.File]::Exists($path))
    # /d blocks AutoRun; delayed expansion OFF. Fixed COMSPEC precedes FOR's
    # child. SYSTEM scheduler/machine configuration is separately trusted.
    $lines=@('@echo off','setlocal EnableExtensions DisableDelayedExpansion',
        ('set "COMSPEC='+$systemDirectory+'\cmd.exe"'),('set "PATH='+$systemDirectory+'"'),
        'for /f "tokens=1 delims==" %%E in (''set'') do set "%%E="',
        ('set "SystemRoot='+$windowsDirectory+'"'),('set "WINDIR='+$windowsDirectory+'"'),
        ('set "COMSPEC='+$systemDirectory+'\cmd.exe"'),('set "PATH='+$systemDirectory+'"'),
        'set "PATHEXT=.EXE;.COM"',('set "TEMP='+$stage+'"'),('set "TMP='+$stage+'"'),
        'set "NoDefaultCurrentDirectoryInExePath=1"','set "RUST_BACKTRACE=0"',
        ('cd /d "'+$stage+'" >nul 2>nul'),'if errorlevel 1 exit /b 90',
        ('"'+$exe+'" --exact '+$Filter+' --ignored --nocapture --test-threads=1 > "'+(Join-Path $stage ($Filter+'.out'))+'" 2>&1'),
        'exit /b %errorlevel%')
    [IO.File]::WriteAllText($path,([string]::Join("`r`n",$lines)+"`r`n"),[Text.Encoding]::ASCII)
    PrivateAcl $path $false
}
function SystemPhase([string]$Filter,[string[]]$Markers,[int]$Seconds) {
    Demand ($Filter -in @('system_matrix','system_cleanup') -and $Seconds -in @(600,120))
    Demand ($watch.Elapsed.TotalMinutes -lt 20); OwnedExeHash; NoNativeProcesses
    $existing=LookupTask
    if ($null -ne $existing) { [void](StopOwnedTask) }
    $out=Join-Path $stage ($Filter+'.out'); Demand (-not [IO.File]::Exists($out))
    PhaseCommand $Filter
    $definition=$scheduler.NewTask(0)
    $definition.RegistrationInfo.Author=$taskName
    $definition.Principal.UserId=$systemSid; $definition.Principal.LogonType=5; $definition.Principal.RunLevel=1
    $definition.Settings.Enabled=$true; $definition.Settings.MultipleInstances=2
    $definition.Settings.AllowDemandStart=$true; $definition.Settings.ExecutionTimeLimit='PT'+$Seconds+'S'
    $definition.Settings.DisallowStartIfOnBatteries=$false; $definition.Settings.StopIfGoingOnBatteries=$false
    Demand ($definition.Triggers.Count -eq 0)
    $action=$definition.Actions.Create(0); $action.Path=$systemDirectory+'\cmd.exe'
    $action.Arguments='/d /s /c ""'+(Join-Path $stage ($Filter+'.cmd'))+'""'; $action.WorkingDirectory=$stage
    $flags=if ($null -eq $existing) { 18 } else { 20 } # CREATE/UPDATE | DONT_ADD_PRINCIPAL_ACE
    $script:taskRegistrationAttempted=$true # BEFORE RPC: partial registration possible.
    $script:registeredCom=$taskFolder.RegisterTaskDefinition($taskName,$definition,$flags,$systemSid,$null,5,'O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)')
    $script:taskRegistered=$true
    TaskIdentity $registeredCom; TaskSecurity $registeredCom
    $fresh=LookupTask; TaskIdentity $fresh; TaskSecurity $fresh
    Demand ($fresh.Enabled -and $fresh.GetInstances(0).Count -eq 0)
    $before=$fresh.LastRunTime.ToUniversalTime(); $timer=[Diagnostics.Stopwatch]::StartNew()
    while ([DateTime]::UtcNow -le $before.AddSeconds(1)) {
        Demand ($timer.Elapsed.TotalSeconds -lt $Seconds); Start-Sleep -Milliseconds 25
    }
    if ($Filter -eq 'system_matrix') { $script:systemMatrixMayHaveRun=$true }
    [void]$registeredCom.Run($null)
    while ($true) {
        $task=LookupTask; TaskIdentity $task; TaskSecurity $task
        if ($task.LastRunTime.ToUniversalTime() -gt $before -and $task.State -in @(1,3) -and $task.GetInstances(0).Count -eq 0) { break }
        Demand ($timer.Elapsed.TotalSeconds -lt $Seconds); Start-Sleep -Milliseconds 100
    }
    Demand ($task.LastTaskResult -eq 0)
    [void](StopOwnedTask) # Disable/no instances/twice native+cmd proof BEFORE read.
    Demand ([IO.FileInfo]::new($out).Length -le 65536)
    Evidence ([IO.File]::ReadAllText($out)) $Markers
    OwnedExeHash
}
function ClosedManifest {
    $manifest=[Collections.Generic.Dictionary[string,bool]]::new([StringComparer]::Ordinal)
    $manifest.Add('',$true); $manifest.Add('fixture',$true)
    $manifest.Add([IO.Path]::GetFileName($exe),$false)
    foreach ($phase in @('system_matrix','system_cleanup')) {
        $manifest.Add(($phase+'.cmd'),$false); $manifest.Add(($phase+'.out'),$false)
    }
    $cases=[Collections.Generic.List[string]]::new()
    $cases.Add('r1'); $cases.Add('r2')
    for ($owner=0; $owner -lt 2; $owner++) { for ($item=0; $item -lt 5; $item++) { $cases.Add(('r3-{0}-{1}' -f $owner,$item)) } }
    for ($item=0; $item -lt 3; $item++) { $cases.Add(('r4-dir-{0}' -f $item)) }
    for ($item=0; $item -lt 4; $item++) { $cases.Add(('r4-file-{0}' -f $item)) }
    $cases.Add('r5'); $cases.Add('r6'); Demand ($cases.Count -eq 21)
    foreach ($case in $cases) {
        $root='fixture/'+$case; $manifest.Add($root,$true)
        $manifest.Add(($root+'/R-TrustTunnel'),$true); $manifest.Add(($root+'/R-TrustTunnel/logs'),$true)
        $files=if ($case -eq 'r5') { @('events.log','events.lock') } else { @('events.log','events.lock','events.tmp','events.log.1') }
        foreach ($file in $files) { $manifest.Add(($root+'/R-TrustTunnel/logs/'+$file),$false) }
        if ($case.StartsWith('r4-dir-',[StringComparison]::Ordinal)) { $manifest.Add(($root+'/canary'),$true) }
        if ($case.StartsWith('r4-file-',[StringComparison]::Ordinal)) { $manifest.Add(($root+'/canary'),$false) }
        # R5 removes its known synthetic canary only AFTER its unchanged rejection
        # assertions; any leftover pair/canary (including panic) is forbidden here.
    }
    # CurrentUser intentionally FORBIDDEN, not skipped. Same hashed SYSTEM native
    # system_cleanup must remove it. Admin never traverses/repairs that leaf.
    return ,$manifest
}
function CleanupStage {
    Demand $canCleanup
    try {
        # Only after task/process/SYSTEM-cleanup gates: acquire DELETE while each
        # runtime reference is STILL live. No close-before-open/identity ABA gap.
        Demand ($null -ne $stagePin -and $stagePin.Handle -ne [IntPtr]::Zero)
        $s=[RTrust107Native]::OwnRoot($stage,$true); $owned.Add($s)
        $facts=[RTrust107Native]::Facts($s)
        Demand ($facts.Volume -eq $stagePin.Facts.Volume -and [RTrust107Native]::Id($facts) -eq [RTrust107Native]::Id($stagePin.Facts) -and [RTrust107Native]::Id($facts) -ne 0 -and ($facts.Attributes -band 0x410) -eq 0x10)
        PrivateAcl $stage $true
        $f=[IntPtr]::Zero
        if ($null -ne $fixturePin) {
            Demand ($fixturePin.Handle -ne [IntPtr]::Zero)
            $f=[RTrust107Native]::Relative($s,'fixture',$true); $owned.Add($f)
            $facts=[RTrust107Native]::Facts($f)
            Demand ($facts.Volume -eq $fixturePin.Facts.Volume -and [RTrust107Native]::Id($facts) -eq [RTrust107Native]::Id($fixturePin.Facts) -and [RTrust107Native]::Id($facts) -ne 0 -and ($facts.Attributes -band 0x410) -eq 0x10)
            PrivateAcl (Join-Path $stage 'fixture') $true
        } else { [RTrust107Native]::Absent((Join-Path $stage 'fixture')) }
        # Both identities/ACLs are proven before releasing EITHER runtime pin.
        foreach ($runtimePin in @($stagePin,$fixturePin)) {
            if ($null -ne $runtimePin) {
                Demand ([RTrust107Native]::CloseHandle($runtimePin.Handle))
                $runtimePin.Handle=[IntPtr]::Zero
            }
        }
        $ownedByRelative.Add('',$s)
        if ($f -ne [IntPtr]::Zero) { $ownedByRelative.Add('fixture',$f) }
    } catch { $script:canCleanup=$false; throw 'cleanup directory acquisition=false' }
    $manifest=ClosedManifest
    $nodes=[Collections.Generic.List[object]]::new(); $queue=[Collections.Generic.Queue[object]]::new()
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal); [void]$seen.Add('')
    $root=[PSCustomObject]@{ Relative=''; Handle=$ownedByRelative['']; Directory=$true; Facts=[RTrust107Native]::Facts($ownedByRelative['']) }
    Demand (($root.Facts.Attributes -band 0x410) -eq 0x10)
    $nodes.Add($root); $queue.Enqueue($root)
    while ($queue.Count -gt 0) {
        $parent=$queue.Dequeue()
        Demand (([RTrust107Native]::Facts($parent.Handle).Attributes -band 0x410) -eq 0x10)
        foreach ($entry in [RTrust107Native]::Entries($parent.Handle)) {
            $relative=if ($parent.Relative.Length) { $parent.Relative+'/'+$entry.Name } else { $entry.Name }
            Demand ($manifest.ContainsKey($relative) -and $nodes.Count -lt 256 -and $seen.Add($relative))
            $directory=$manifest[$relative]
            Demand (($entry.Attributes -band 0x400) -eq 0 -and (($entry.Attributes -band 0x10) -ne 0) -eq $directory)
            if ($ownedByRelative.ContainsKey($relative)) { $handle=$ownedByRelative[$relative] }
            else {
                $handle=[RTrust107Native]::Relative($parent.Handle,$entry.Name,$directory)
                $owned.Add($handle); $ownedByRelative.Add($relative,$handle)
            }
            $facts=[RTrust107Native]::Facts($handle)
            Demand ($facts.Volume -eq $root.Facts.Volume -and [RTrust107Native]::Id($facts) -eq $entry.Id -and $entry.Id -ne 0)
            Demand (($facts.Attributes -band 0x400) -eq 0 -and (($facts.Attributes -band 0x10) -ne 0) -eq $directory)
            if (-not $directory) { Demand ($facts.Links -eq 1) }
            $node=[PSCustomObject]@{ Relative=$relative; Handle=$handle; Directory=$directory; Facts=$facts }
            $nodes.Add($node); if ($directory) { $queue.Enqueue($node) }
        }
    }
    # r3-1-* is BU-owned: NO owner trust, ACL repair, pathname recursion/deletion.
    # All files, including R5, MUST be single-link. No share-DELETE exception.
    # Link-count checks do not freeze an adversary's metadata; each actual unlink
    # is confined to the retained opened link, with share-DELETE withheld.
    # Validate WHOLE bounded namespace before any unlink. Reverse BFS is postorder.
    for ($index=$nodes.Count-1; $index -ge 0; $index--) {
        $node=$nodes[$index]; $fresh=[RTrust107Native]::Facts($node.Handle)
        Demand ($fresh.Volume -eq $node.Facts.Volume -and [RTrust107Native]::Id($fresh) -eq [RTrust107Native]::Id($node.Facts) -and ($fresh.Attributes -band 0x400) -eq 0)
        Demand ((($fresh.Attributes -band 0x10) -ne 0) -eq $node.Directory)
        if ($node.Directory) { Demand ([RTrust107Native]::Entries($node.Handle).Length -eq 0) }
        else { Demand ($fresh.Links -eq 1) }
        # Ordinary disposition ONLY; no POSIX/ignore-readonly flags. Concurrent
        # unknown children/type/ACL changes retain/FAIL, never recurse/take over.
        [RTrust107Native]::Unlink($node.Handle)
        Demand ([RTrust107Native]::CloseHandle($node.Handle)); [void]$owned.Remove($node.Handle)
    }
    # ProgramData references remain live; checked ACLs exclude foreign renames.
    [RTrust107Native]::Absent($stage) # ONLY ERROR_FILE_NOT_FOUND proves final name absence.
}
try {
    foreach ($inputPath in @($ArtifactPath,$SourceDirectory,$GitPath)) { Demand ([IO.Path]::IsPathRooted($inputPath)) }
    $ArtifactPath=[IO.Path]::GetFullPath($ArtifactPath); $SourceDirectory=[IO.Path]::GetFullPath($SourceDirectory)
    Demand ([IO.Path]::GetFileName($ArtifactPath) -cmatch '^windows_native_acceptance-[0-9a-f]+\.exe$')
    foreach ($path in @($ArtifactPath,$SourceDirectory,$ProtectedBuildRoot,$programData,$systemDirectory,$windowsDirectory,$bootstrap)) { [void](SafeLiteral $path) }
    Ancestors $programData; Ancestors $systemDirectory; Ancestors $windowsDirectory
    BuildChain $SourceDirectory $false; BuildChain $ArtifactPath $true; BuildChain $bootstrap $false
    foreach ($module in @('Microsoft.PowerShell.Utility','Microsoft.PowerShell.Security','Microsoft.PowerShell.Management','CimCmdlets','ScheduledTasks')) {
        PinTrustedTree ($trustedShell+'\Modules\'+$module) 4096
    }
    Ancestors $trustedShell; OsProtected ($trustedShell+'\powershell.exe'); [void](PinFile ($trustedShell+'\powershell.exe'))
    OsProtected ($systemDirectory+'\cmd.exe'); [void](PinFile ($systemDirectory+'\cmd.exe'))
    $sourceInputs=@('ci/issue107_windows_native.ps1','crates/journal/tests/windows_native_acceptance.rs')
    VerifySourceGit
    $artifactLength=[IO.FileInfo]::new($ArtifactPath).Length
    Demand ($artifactLength -gt 256 -and $artifactLength -le 64MB)
    Demand ((Get-FileHash -LiteralPath $ArtifactPath -Algorithm SHA256).Hash -ieq $ExpectedSha256)
    $stage=Join-Path $programData ('RTrust107J-'+$guid); $taskName='RTrust107J-'+$guid
    [void](SafeLiteral $stage)
    Demand ([IO.DriveInfo]::new([IO.Path]::GetPathRoot($stage)).DriveFormat -ceq 'NTFS')
    $stagePin=NewPrivateDirectory $stage $true; $stageCreated=$true
    $fixture=Join-Path $stage 'fixture'; $fixturePin=NewPrivateDirectory $fixture $true
    $exe=Join-Path $stage ('j-'+$guid+'.exe')
    # Creation writer closed before retention. NO staged readonly/no-delete pin.
    $source=[IO.File]::Open($ArtifactPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $destination=[IO.File]::Open($exe,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $source.CopyTo($destination); $destination.Flush($true) } finally { $destination.Dispose() }
    } finally { $source.Dispose() }
    $exeHandle=[RTrust107Native]::OwnRoot($exe,$false); $owned.Add($exeHandle); $ownedByRelative.Add([IO.Path]::GetFileName($exe),$exeHandle)
    PrivateAcl $exe $false; OwnedExeHash
    # Literal strict parser opens FileShare.Read, incompatible with our DELETE pin.
    # Parse ORIGINAL protected/pinned artifact; hash binds EXACT same PE bytes.
    # Only staged exe runs, and its private adjacent namespace contains no DLLs.
    RequireLoaderProof $ArtifactPath
    $scheduler=New-Object -ComObject 'Schedule.Service'; $scheduler.Connect(); $taskFolder=$scheduler.GetFolder('\')
    if ($null -ne (LookupTask)) { $canCleanup=$false; Demand $false }
    NoNativeProcesses
    SystemPhase 'system_matrix' @('PASS: R1 ','PASS: R2 ','PASS: R3 ','PASS: R4 ','PASS: R5 ','PASS: R6 ','PASS: SYSTEM_PRIVATE_POSITIVE','PASS: SYSTEM_MATRIX_COMPLETE') 600
    Write-Output 'PASS: SYSTEM matrix exact one test and all markers'
    $text=Run $exe '--exact restricted_admin_matrix --ignored --nocapture --test-threads=1' 120000 $false @{ NoDefaultCurrentDirectoryInExePath='1'; RUST_BACKTRACE='0' } 65536
    Evidence $text @('PASS: R7 ','PASS: R8 ','PASS: ADMIN_MATRIX_COMPLETE')
    NoNativeProcesses; OwnedExeHash
    Write-Output 'PASS: restricted-token matrix exact one test; NOT another desktop login'
} catch { $failed=$true }
finally {
    if ($taskRegistrationAttempted) {
        try {
            [void](StopOwnedTask); Demand $canCleanup
            if ($systemMatrixMayHaveRun) {
                SystemPhase 'system_cleanup' @('PASS: SYSTEM_CLEANUP_COMPLETE') 120
                Write-Output 'PASS: SYSTEM cleanup-only exact one test and process exit'
            }
        } catch { $canCleanup=$false; $failed=$true }
        try {
            $task=StopOwnedTask # Still try disable/control after earlier uncertainty.
            Demand $canCleanup
            if ($null -ne $task) {
                Quiescent $task; Start-Sleep -Milliseconds 250; Quiescent (LookupTask)
                $taskFolder.DeleteTask($taskName,0)
            }
            Demand ($null -eq (LookupTask)); NoNativeProcesses
            Start-Sleep -Milliseconds 250; NoNativeProcesses
            $taskRegistered=$false
        } catch { $canCleanup=$false; $failed=$true }
    }
    if ($stageCreated -and $canCleanup) {
        try {
            if ($taskRegistrationAttempted) { Demand ($null -eq (LookupTask)); NoNativeProcesses }
            CleanupStage
            Write-Output 'PASS: temporary task absent and bounded handle fixture cleanup complete'
        } catch { $canCleanup=$false; $failed=$true }
    }
    if (-not $canCleanup) { $failed=$true; Write-Output 'FAIL: native cleanup unproven; task/stage retained where present; human review required' }
    if ($taskRegistered -or ($taskRegistrationAttempted -and -not $canCleanup)) {
        try {
            $remaining=LookupTask
            if ($null -eq $remaining) { Write-Output 'PASS: native task confirmed absent; fixture cleanup result separate' }
            elseif ($remaining.Enabled) { Write-Output 'FAIL: native task may remain ENABLED; no triggers but demand start possible; stage retained' }
            else { Write-Output 'FAIL: native task retained DISABLED; stage retained; cleanup incomplete' }
        } catch { Write-Output 'FAIL: native task state UNKNOWN; may remain enabled; stage retained' }
    }
    # Release only after unlink/retention decision. NO pathname deletion afterward.
    foreach ($runtimePin in @($stagePin,$fixturePin)) {
        if ($null -ne $runtimePin -and $runtimePin.Handle -ne [IntPtr]::Zero) {
            if (-not [RTrust107Native]::CloseHandle($runtimePin.Handle)) { $failed=$true }
            else { $runtimePin.Handle=[IntPtr]::Zero }
        }
    }
    foreach ($handle in $owned) { if (-not [RTrust107Native]::CloseHandle($handle)) { $failed=$true } }
    foreach ($handle in $pins) { if (-not [RTrust107Native]::CloseHandle($handle)) { $failed=$true } }
    Write-Output 'NOT RUN: compiler bootstrap cleanup; protected temporary files retained'
}
if ($failed) { Write-Output 'FAIL: native launcher (details suppressed; gates not passed)'; exit 1 }
exit 0
