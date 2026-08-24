<#
.SYNOPSIS
    Enumerates AV/EDR path (and extension/process) exclusions on the local
    host, using both registry and event-log based detection across several
    common products.

.DESCRIPTION
    Useful for CTF/lab post-exploitation enumeration (e.g. HTB Mist-style
    boxes) where an AV exclusion path can be abused to drop a payload
    undetected. Rather than hardcoding one Event ID for one AV, this script:

      1. Detects which AV/EDR products appear to be installed.
      2. Reads exclusions directly from the registry where possible
         (fastest, most reliable, doesn't depend on log retention).
      3. Cross-checks against relevant Windows Event Log channels, with a
         list of candidate Event IDs per product instead of a single
         hardcoded one - since IDs vary by product version/config.

    Run as Administrator for full registry access (HKLM policy keys in
    particular often require elevation).

.NOTES
    Only enumerates local configuration. Intended for authorized testing /
    CTF environments.
    Manual Command (Of 5007):
    Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -FilterXPath "*[System[(EventID=5007)]]" | Where-Object { $_.Message -like "*Exclusions\Paths*" } | Select-Object -Property TimeCreated, Id, Message | Format-List
#>

[CmdletBinding()]
param(
    # Also dump raw matching event log messages, not just parsed exclusions
    [switch]$ShowRawEvents
)

function Write-Section($title) {
    Write-Host "`n=== $title ===" -ForegroundColor Cyan
}

$foundAny = $false

# ---------------------------------------------------------------------------
# 1. Detect installed AV/EDR products via WMI SecurityCenter2 + common paths
# ---------------------------------------------------------------------------
Write-Section "Installed AV/EDR products (SecurityCenter2)"
try {
    $avProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop
    if ($avProducts) {
        $avProducts | Select-Object displayName, productState, pathToSignedProductExe | Format-Table -AutoSize
    } else {
        Write-Host "No products registered in SecurityCenter2 (may be a server SKU, which doesn't populate this)." -ForegroundColor Yellow
    }
} catch {
    Write-Host "Could not query SecurityCenter2: $($_.Exception.Message)" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 2. Windows Defender - registry exclusions (most reliable, no log needed)
# ---------------------------------------------------------------------------
Write-Section "Windows Defender - Registry Exclusions"

$defenderRegPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths',
    'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions',
    'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes',
    'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\IpAddresses',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Extensions',
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes'
)

foreach ($path in $defenderRegPaths) {
    if (Test-Path $path) {
        $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        $names = $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
        if ($names) {
            $foundAny = $true
            Write-Host "`n[$path]" -ForegroundColor Green
            $names | ForEach-Object { Write-Host "  $($_.Name)" }
        }
    }
}

# Also try the Defender PowerShell cmdlet if the module is present (cleanest source)
if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
    Write-Host "`n[Get-MpPreference]" -ForegroundColor Green
    try {
        $mp = Get-MpPreference
        [PSCustomObject]@{
            ExclusionPath      = $mp.ExclusionPath -join '; '
            ExclusionExtension = $mp.ExclusionExtension -join '; '
            ExclusionProcess   = $mp.ExclusionProcess -join '; '
            ExclusionIpAddress = $mp.ExclusionIpAddress -join '; '
        } | Format-List
        if ($mp.ExclusionPath -or $mp.ExclusionExtension -or $mp.ExclusionProcess) { $foundAny = $true }
    } catch {
        Write-Host "  Get-MpPreference failed (needs elevation / module not loaded): $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

if (-not $foundAny) {
    Write-Host "No Defender exclusions found via registry/cmdlet." -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# 3. Windows Defender - Event Log (multiple candidate Event IDs)
# ---------------------------------------------------------------------------
Write-Section "Windows Defender - Event Log"

# Different Defender builds/actions log exclusion changes under different
# IDs. 5007 = config value changed (classic HTB Mist case). 1116/1117 =
# detection/action taken (can reveal exclusions indirectly). Included as a
# broad net rather than a single hardcoded ID.
$defenderEventIds = 5007, 1116, 1117, 1121, 1126

try {
    $defenderEvents = Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -ErrorAction Stop |
        Where-Object { $_.Id -in $defenderEventIds -and $_.Message -like "*Exclusions*" }

    if ($defenderEvents) {
        $foundAny = $true
        $defenderEvents | Select-Object TimeCreated, Id, @{N='Summary';E={($_.Message -split "`n")[0..3] -join ' | '}} |
            Format-Table -Wrap -AutoSize

        if ($ShowRawEvents) {
            $defenderEvents | Select-Object TimeCreated, Id, Message | Format-List
        }
    } else {
        Write-Host "No exclusion-related events found in Defender log (IDs checked: $($defenderEventIds -join ', '))." -ForegroundColor DarkGray
    }
} catch {
    Write-Host "Defender operational log not accessible or doesn't exist on this host: $($_.Exception.Message)" -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# 4. Other common AV products - registry-based exclusion locations
# ---------------------------------------------------------------------------
Write-Section "Other AV products - Registry Exclusions"

# Map of product name -> known exclusion registry locations. Extend this
# table as needed for whatever's actually installed on the box.
$otherAvRegistryMap = @{
    'Sophos'          = @(
        'HKLM:\SOFTWARE\Sophos\Sophos Anti-Virus\Exclusions*'
    )
    'McAfee'          = @(
        'HKLM:\SOFTWARE\McAfee\AVEngine\OAS\DefaultSettings\ExcludedItems',
        'HKLM:\SOFTWARE\McAfee\AVEngine\OAS\OnDemandSettings\ExcludedItems'
    )
    'Symantec'        = @(
        'HKLM:\SOFTWARE\Symantec\Symantec Endpoint Protection\AV\Exclusions'
    )
    'Trend Micro'     = @(
        'HKLM:\SOFTWARE\TrendMicro\PC-cillinNTCorp\CurrentVersion\Real Time Scan Configuration\ExcludePath'
    )
    'ESET'            = @(
        'HKLM:\SOFTWARE\ESET\ESET Security\CurrentVersion\Info\Exclusions'
    )
    'Kaspersky'       = @(
        'HKLM:\SOFTWARE\KasperskyLab\protected\*\exclusions'
    )
    'CrowdStrike Falcon' = @(
        'HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent\Sim'
    )
}

$anyOtherFound = $false
foreach ($avName in $otherAvRegistryMap.Keys) {
    foreach ($regPattern in $otherAvRegistryMap[$avName]) {
        $matchedPaths = Get-Item -Path $regPattern -ErrorAction SilentlyContinue
        if ($matchedPaths) {
            $anyOtherFound = $true
            $foundAny = $true
            foreach ($mp in $matchedPaths) {
                Write-Host "`n[$avName] $($mp.PSPath -replace '.*::','')" -ForegroundColor Green
                $props = Get-ItemProperty -Path $mp.PSPath -ErrorAction SilentlyContinue
                $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                    Write-Host "  $($_.Name) = $($_.Value)"
                }
            }
        }
    }
}
if (-not $anyOtherFound) {
    Write-Host "No known third-party AV exclusion registry keys found (checked: $($otherAvRegistryMap.Keys -join ', '))." -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# 5. Generic sweep: any Application/System event mentioning "exclusion"
# ---------------------------------------------------------------------------
Write-Section "Generic sweep - Application/System logs mentioning 'exclusion'"

try {
    $genericEvents = Get-WinEvent -LogName Application, System -ErrorAction Stop -MaxEvents 2000 |
        Where-Object { $_.Message -match 'exclu(de|sion)' }

    if ($genericEvents) {
        $foundAny = $true
        $genericEvents | Select-Object TimeCreated, LogName, Id, ProviderName |
            Format-Table -AutoSize
    } else {
        Write-Host "No matches in the most recent 2000 Application/System events." -ForegroundColor DarkGray
    }
} catch {
    Write-Host "Generic log sweep failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
Write-Section "Summary"
if ($foundAny) {
    Write-Host "Exclusion data was found - review the sections above." -ForegroundColor Green
} else {
    Write-Host "No exclusions detected via any method. Try running elevated, or check if a non-listed AV/EDR product is installed (Get-Service, Get-Process, installed program list)." -ForegroundColor Yellow
}