<#
.SYNOPSIS
    Enables all Windows privileges currently held (but disabled) on the
    current process token.

.DESCRIPTION
    Windows tokens carry a fixed list of privileges assigned by group
    membership / local security policy. Many of them are present but in a
    "Disabled" state by default (e.g. SeDebugPrivilege, SeBackupPrivilege).
    This script uses AdjustTokenPrivileges via P/Invoke to flip every
    privilege already present on the current token to "Enabled".

    It CANNOT grant a privilege that isn't already assigned to the account
    running the script - it only toggles the state of privileges you
    already have. Run PowerShell "as Administrator" for this to have any
    real effect, since most useful privileges are only assigned to admin
    tokens in the first place.

.NOTES
    Because the token is destroyed and recreated for every new process,
    this only affects the current PowerShell session/process (and children
    that inherit the handle). It is not persistent across new sessions -
    that's expected Windows behavior, not a bug in the script.
#>

[CmdletBinding()]
param(
    # Show the before/after privilege table
    [switch]$ShowResult
)

$signature = @'
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;

public class TokenPriv
{
    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public const uint TOKEN_QUERY = 0x0008;
    public const uint SE_PRIVILEGE_ENABLED = 0x00000002;

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle,
        bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        uint BufferLengthInBytes,
        IntPtr PreviousState,
        IntPtr ReturnLengthInBytes);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    public static bool EnablePrivilege(string privilege)
    {
        IntPtr hToken;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
            return false;

        try
        {
            LUID luid;
            if (!LookupPrivilegeValue(null, privilege, out luid))
                return false;

            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.PrivilegeCount = 1;
            tp.Luid = luid;
            tp.Attributes = SE_PRIVILEGE_ENABLED;

            bool ok = AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            // AdjustTokenPrivileges can return true but set ERROR_NOT_ALL_ASSIGNED
            // (1300) if the privilege isn't actually held by the token.
            int err = Marshal.GetLastWin32Error();
            return ok && err == 0;
        }
        finally
        {
            CloseHandle(hToken);
        }
    }
}
'@

Add-Type -TypeDefinition $signature -Language CSharp -ErrorAction SilentlyContinue

# Every privilege constant Windows defines. Not all will exist on your
# token - that's fine, EnablePrivilege just returns $false for those.
$allPrivileges = @(
    'SeAssignPrimaryTokenPrivilege',
    'SeAuditPrivilege',
    'SeBackupPrivilege',
    'SeChangeNotifyPrivilege',
    'SeCreateGlobalPrivilege',
    'SeCreatePagefilePrivilege',
    'SeCreatePermanentPrivilege',
    'SeCreateSymbolicLinkPrivilege',
    'SeCreateTokenPrivilege',
    'SeDebugPrivilege',
    'SeDelegateSessionUserImpersonatePrivilege',
    'SeEnableDelegationPrivilege',
    'SeImpersonatePrivilege',
    'SeIncreaseBasePriorityPrivilege',
    'SeIncreaseQuotaPrivilege',
    'SeIncreaseWorkingSetPrivilege',
    'SeLoadDriverPrivilege',
    'SeLockMemoryPrivilege',
    'SeMachineAccountPrivilege',
    'SeManageVolumePrivilege',
    'SeProfileSingleProcessPrivilege',
    'SeRelabelPrivilege',
    'SeRemoteShutdownPrivilege',
    'SeRestorePrivilege',
    'SeSecurityPrivilege',
    'SeShutdownPrivilege',
    'SeSyncAgentPrivilege',
    'SeSystemEnvironmentPrivilege',
    'SeSystemProfilePrivilege',
    'SeSystemtimePrivilege',
    'SeTakeOwnershipPrivilege',
    'SeTcbPrivilege',
    'SeTimeZonePrivilege',
    'SeTrustedCredManAccessPrivilege',
    'SeUndockPrivilege',
    'SeUnsolicitedInputPrivilege'
)

Write-Host "Attempting to enable privileges on current process token..." -ForegroundColor Cyan
Write-Host ""

$results = foreach ($priv in $allPrivileges) {
    $enabled = [TokenPriv]::EnablePrivilege($priv)
    [PSCustomObject]@{
        Privilege = $priv
        Result    = if ($enabled) { 'Enabled' } else { 'Not held / unavailable' }
    }
}

$results | Format-Table -AutoSize

$successCount = ($results | Where-Object { $_.Result -eq 'Enabled' }).Count
Write-Host "`n$successCount of $($allPrivileges.Count) privileges enabled on this token." -ForegroundColor Green

if ($ShowResult) {
    Write-Host "`nCurrent effective privileges (whoami /priv):" -ForegroundColor Cyan
    whoami /priv
}