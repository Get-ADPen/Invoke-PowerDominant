$modeStrict = $args -contains '--strict'
$showHelp   = $args -contains '--help'

if ($showHelp) {
@"
ActiveProcessHunt.ps1 (rev2)

Usage:
  .\ActiveProcessHunt.ps1           Default - skips System32, SysWOW64, WinSxS
  .\ActiveProcessHunt.ps1 --strict  No path exclusions - catches misconfigured ACLs anywhere
  .\ActiveProcessHunt.ps1 --help    This message

Finding types:
  FileWrite  - ACL grants write/modify; stop the service first if binary is locked
  DirWrite   - Parent directory writable; plant or DLL hijack
  Unquoted   - Unquoted service path with spaces; writable intermediate dir
"@
    exit 0
}

$skipPrefixes = @(
    "$env:SystemRoot\System32\",
    "$env:SystemRoot\SysWOW64\",
    "$env:SystemRoot\WinSxS\",
    "C:\Program Files\WindowsApps\"
)

function Should-Skip {
    param([string]$Path)
    if ($modeStrict) { return $false }
    foreach ($p in $skipPrefixes) { if ($Path -like "$p*") { return $true } }
    return $false
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$mySIDs   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
try { [void]$mySIDs.Add($identity.User.Value) } catch {}
foreach ($g in $identity.Groups) { try { [void]$mySIDs.Add($g.Value) } catch {} }

$WRITE_MASK = [int]([System.Security.AccessControl.FileSystemRights]::WriteData)  -bor
              [int]([System.Security.AccessControl.FileSystemRights]::Write)       -bor
              [int]([System.Security.AccessControl.FileSystemRights]::Modify)      -bor
              [int]([System.Security.AccessControl.FileSystemRights]::FullControl)

$DIR_MASK   = [int]([System.Security.AccessControl.FileSystemRights]::CreateFiles) -bor
              [int]([System.Security.AccessControl.FileSystemRights]::Write)        -bor
              [int]([System.Security.AccessControl.FileSystemRights]::Modify)       -bor
              [int]([System.Security.AccessControl.FileSystemRights]::FullControl)

function Test-WriteACL {
    param([string]$Path)
    if (-not (Test-Path $Path -PathType Leaf -ErrorAction SilentlyContinue)) { return $false }
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -ne 'Allow') { continue }
            if (-not $mySIDs.Contains($rule.IdentityReference.Value)) { continue }
            if ([int]$rule.FileSystemRights -band $WRITE_MASK) { return $true }
        }
    } catch {}
    return $false
}

function Test-DirWriteACL {
    param([string]$Path)
    if (-not (Test-Path $Path -PathType Container -ErrorAction SilentlyContinue)) { return $false }
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -ne 'Allow') { continue }
            if (-not $mySIDs.Contains($rule.IdentityReference.Value)) { continue }
            if ([int]$rule.FileSystemRights -band $DIR_MASK) { return $true }
        }
    } catch {}
    return $false
}

function Resolve-BinaryPath {
    param([string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
    $Raw = $Raw.Trim()
    $Raw = [System.Environment]::ExpandEnvironmentVariables($Raw)
    if ($Raw -match '^"([^"]+)"') { return $Matches[1] }
    $tokens = $Raw -split '\s+'
    $built  = ''
    foreach ($tok in $tokens) {
        $built = if ($built -eq '') { $tok } else { "$built $tok" }
        if (Test-Path $built -PathType Leaf -ErrorAction SilentlyContinue) { return $built }
    }
    if ($Raw -match '([A-Za-z]:\\[^\s"]+\.(exe|bat|ps1|cmd|vbs))') { return $Matches[1] }
    $first = $tokens[0]
    if ($first -match '^[A-Za-z]:\\') { return $first }
    return $null
}

function Get-UnquotedCandidates {
    param([string]$Raw, [string]$Name)
    $found = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $found }
    $Raw = $Raw.Trim()
    if ($Raw.StartsWith('"') -or $Raw -notmatch ' ') { return $found }
    $parts   = $Raw -split '\\'
    $current = ''
    foreach ($part in $parts) {
        if ($part -match ' ') {
            $plantName = ($part -split ' ')[0] + '.exe'
            if ($current -ne '' -and (Test-DirWriteACL $current)) {
                $found.Add([PSCustomObject]@{ Name = $Name; Plant = Join-Path $current $plantName; Dir = $current })
            }
        }
        $current = if ($current -eq '') { $part } else { "$current\$part" }
    }
    return $found
}

$results  = [System.Collections.Generic.List[PSCustomObject]]::new()
$seen     = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$svcCount = 0

function Add-Finding {
    param($Source, $Name, $Path, $Dir, $Type)
    $key = "${Source}|${Type}|${Path}"
    if ($seen.Add($key)) {
        $results.Add([PSCustomObject]@{ Source = $Source; Name = $Name; Path = $Path; Dir = $Dir; Type = $Type })
    }
}

function Process-Binary {
    param([string]$Source, [string]$Name, [string]$RawPath)
    $bin = Resolve-BinaryPath $RawPath
    if (-not $bin) { return }
    if (Should-Skip $bin) { return }
    $dir = Split-Path $bin -Parent -ErrorAction SilentlyContinue
    if (-not $dir) { return }
    if (Test-WriteACL $bin)    { Add-Finding $Source $Name $bin $dir 'FileWrite' }
    if (Test-DirWriteACL $dir) { Add-Finding $Source $Name $bin $dir 'DirWrite'  }
}

Write-Host "[*] Services (WMI)..." -ForegroundColor DarkGray
try {
    $services = Get-CimInstance Win32_Service -ErrorAction Stop
    $svcCount = $services.Count
    foreach ($svc in $services) {
        if ([string]::IsNullOrWhiteSpace($svc.PathName)) { continue }
        Process-Binary 'Service' $svc.Name $svc.PathName
        foreach ($uq in (Get-UnquotedCandidates $svc.PathName $svc.Name)) {
            Add-Finding 'Service' $uq.Name $uq.Plant $uq.Dir 'Unquoted'
        }
    }
} catch { Write-Host "  [-] WMI: $_" -ForegroundColor DarkGray }

Write-Host "[*] Services (Registry)..." -ForegroundColor DarkGray
$regSvcBase = 'HKLM:\SYSTEM\CurrentControlSet\Services'
if (Test-Path $regSvcBase) {
    Get-ChildItem $regSvcBase -ErrorAction SilentlyContinue | ForEach-Object {
        $imgPath = (Get-ItemProperty $_.PSPath -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
        if ([string]::IsNullOrWhiteSpace($imgPath)) { return }
        $name = $_.PSChildName
        Process-Binary 'Service(reg)' $name $imgPath
        foreach ($uq in (Get-UnquotedCandidates $imgPath $name)) {
            Add-Finding 'Service(reg)' $uq.Name $uq.Plant $uq.Dir 'Unquoted'
        }
    }
}

Write-Host "[*] Scheduled tasks..." -ForegroundColor DarkGray
try {
    foreach ($task in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        foreach ($action in $task.Actions) {
            $exe = $action.Execute
            if ([string]::IsNullOrWhiteSpace($exe)) { continue }
            $exe  = [System.Environment]::ExpandEnvironmentVariables($exe)
            $full = if ($action.Arguments) { "$exe $($action.Arguments)" } else { $exe }
            Process-Binary 'Task' "$($task.TaskPath)$($task.TaskName)" $full
        }
    }
} catch { Write-Host "  [-] Tasks: $_" -ForegroundColor DarkGray }

Write-Host "[*] Startup (registry)..." -ForegroundColor DarkGray
$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
foreach ($key in $runKeys) {
    if (-not (Test-Path $key -ErrorAction SilentlyContinue)) { continue }
    $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
    $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
        Process-Binary 'Startup' $_.Name $_.Value
    }
}

Write-Host "[*] Startup (folders)..." -ForegroundColor DarkGray
@(
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
) | ForEach-Object {
    if (-not (Test-Path $_)) { return }
    Get-ChildItem $_ -Force -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } | ForEach-Object {
        $bin = $_.FullName; $dir = $_.DirectoryName
        if (Should-Skip $bin) { return }
        if (Test-WriteACL $bin)    { Add-Finding 'Startup' 'StartupFolder' $bin $dir 'FileWrite' }
        if (Test-DirWriteACL $dir) { Add-Finding 'Startup' 'StartupFolder' $bin $dir 'DirWrite'  }
    }
}

Write-Host ""

if ($results.Count -eq 0) {
    Write-Host "No writable targets found." -ForegroundColor Green
    Write-Host "Services scanned (WMI): $svcCount" -ForegroundColor DarkGray
    if (-not $modeStrict) { Write-Host "Try --strict to include System32/SysWOW64." -ForegroundColor DarkGray }
    exit 0
}

$typeOrder = @{ FileWrite = 0; Unquoted = 1; DirWrite = 2 }
$sorted    = $results | Sort-Object { $typeOrder[$_.Type] }, Source, Name

$fileWrite = $sorted | Where-Object { $_.Type -eq 'FileWrite' }
$unquoted  = $sorted | Where-Object { $_.Type -eq 'Unquoted' }
$fwPaths   = @($fileWrite | Select-Object -ExpandProperty Path)
$dirWrite  = $sorted | Where-Object { $_.Type -eq 'DirWrite' -and $fwPaths -notcontains $_.Path }

$modeLabel = if ($modeStrict) { '[STRICT]' } else { '[DEFAULT]' }
Write-Host "=== ActiveProcessHunt $modeLabel ===" -ForegroundColor Cyan
Write-Host ""

if ($fileWrite) {
    Write-Host "[FileWrite] Overwrite directly - stop service first if locked" -ForegroundColor Red
    $fileWrite | ForEach-Object {
        Write-Host "  [$($_.Source.PadRight(12))] $($_.Name)"
        Write-Host "               $($_.Path)"
    }
    Write-Host ""
}

if ($unquoted) {
    Write-Host "[Unquoted]  Plant here - triggers on service restart" -ForegroundColor Yellow
    $unquoted | ForEach-Object {
        Write-Host "  [$($_.Source.PadRight(12))] $($_.Name)"
        Write-Host "               Plant : $($_.Path)"
        Write-Host "               Dir   : $($_.Dir)"
    }
    Write-Host ""
}

if ($dirWrite) {
    Write-Host "[DirWrite]  Parent writable - DLL hijack or replace on restart" -ForegroundColor Magenta
    $dirWrite | ForEach-Object {
        Write-Host "  [$($_.Source.PadRight(12))] $($_.Name)"
        Write-Host "               Binary: $($_.Path)"
        Write-Host "               Dir   : $($_.Dir)"
    }
    Write-Host ""
}

$total = $fileWrite.Count + $unquoted.Count + $dirWrite.Count
Write-Host "Total: $total  (FileWrite:$($fileWrite.Count)  Unquoted:$($unquoted.Count)  DirWrite:$($dirWrite.Count))" -ForegroundColor DarkGray
if (-not $modeStrict) { Write-Host "Run --strict to include System32/SysWOW64." -ForegroundColor DarkGray }