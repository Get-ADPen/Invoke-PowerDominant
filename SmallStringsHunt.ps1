function Is-Boring {
    param([string]$Val)
    if ([string]::IsNullOrWhiteSpace($Val)) { return $true }
    foreach ($p in @('^\s*$','^CN=','^DC=','^S-1-','^\{[0-9A-Fa-f\-]{36}\}$','^\d+$')) {
        if ($Val -match $p) { return $true }
    }
    return $false
}

function Is-CredLike {
    param([string]$Val)
    if ($Val.Length -lt 8) { return $false }
    $score = 0
    if ($Val -cmatch '[A-Z]')          { $score++ }
    if ($Val -cmatch '[a-z]')          { $score++ }
    if ($Val -match '\d')              { $score++ }
    if ($Val -match '[^a-zA-Z0-9\s]') { $score++ }
    return ($score -ge 3 -or ($score -ge 2 -and $Val.Length -ge 14))
}

function Get-Searcher {
    param([string]$Filter, [string[]]$Props)
    try {
        $root = [System.DirectoryServices.DirectoryEntry]::new()
        $s    = [System.DirectoryServices.DirectorySearcher]::new($root, $Filter)
        $s.PageSize = 1000
        foreach ($p in $Props) { [void]$s.PropertiesToLoad.Add($p) }
        return $s
    } catch {
        Write-Host "[-] LDAP bind failed: $_" -ForegroundColor Red
        return $null
    }
}

function Extract-Val {
    param($Entry, [string]$Attr)
    if (-not $Entry.Properties.Contains($Attr)) { return $null }
    $vals = $Entry.Properties[$Attr]
    if ($vals.Count -eq 0) { return $null }
    return ($vals | ForEach-Object { $_.ToString() }) -join '; '
}

$findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Finding {
    param($Type, $Object, $Attr, $Val)
    $findings.Add([PSCustomObject]@{
        Type     = $Type
        Object   = $Object
        Attr     = $Attr
        Value    = $Val
        CredLike = Is-CredLike $Val
    })
}

$userAttribs = @(
    'sAMAccountName','description','info','comment','adminDescription','adminDisplayName',
    'wWWHomePage','url','homeDirectory','scriptPath','profilePath',
    'streetAddress','personalTitle','company','department','physicalDeliveryOfficeName',
    'userPassword',
    'extensionAttribute1','extensionAttribute2','extensionAttribute3','extensionAttribute4',
    'extensionAttribute5','extensionAttribute6','extensionAttribute7','extensionAttribute8',
    'extensionAttribute9','extensionAttribute10','extensionAttribute11','extensionAttribute12',
    'extensionAttribute13','extensionAttribute14','extensionAttribute15'
)

$computerAttribs = @(
    'sAMAccountName','description','info','comment','adminDescription','location','operatingSystemVersion'
)

$groupAttribs = @(
    'sAMAccountName','description','info','comment','adminDescription','adminDisplayName'
)

$ouAttribs     = @('name','description','info','adminDescription')
$gpoAttribs    = @('displayName','description','adminDescription','gPCFileSysPath')
$printerAttribs = @('printerName','description','comment','location','portName','adminDescription')

Write-Host "[*] Users..." -ForegroundColor DarkGray
$s = Get-Searcher '(&(objectCategory=person)(objectClass=user))' $userAttribs
if ($s) {
    $r = $s.FindAll()
    foreach ($entry in $r) {
        $sam = Extract-Val $entry 'sAMAccountName'
        foreach ($attr in ($userAttribs | Where-Object { $_ -ne 'sAMAccountName' })) {
            $val = Extract-Val $entry $attr
            if ($val -and -not (Is-Boring $val)) { Add-Finding 'User' $sam $attr $val }
        }
    }
    $r.Dispose()
}

Write-Host "[*] Computers..." -ForegroundColor DarkGray
$s = Get-Searcher '(objectCategory=computer)' $computerAttribs
if ($s) {
    $r = $s.FindAll()
    foreach ($entry in $r) {
        $sam = (Extract-Val $entry 'sAMAccountName') -replace '\$$', ''
        foreach ($attr in ($computerAttribs | Where-Object { $_ -ne 'sAMAccountName' })) {
            $val = Extract-Val $entry $attr
            if ($val -and -not (Is-Boring $val)) { Add-Finding 'Computer' $sam $attr $val }
        }
    }
    $r.Dispose()
}

Write-Host "[*] Groups..." -ForegroundColor DarkGray
$s = Get-Searcher '(objectCategory=group)' $groupAttribs
if ($s) {
    $r = $s.FindAll()
    foreach ($entry in $r) {
        $sam = Extract-Val $entry 'sAMAccountName'
        foreach ($attr in ($groupAttribs | Where-Object { $_ -ne 'sAMAccountName' })) {
            $val = Extract-Val $entry $attr
            if ($val -and -not (Is-Boring $val)) { Add-Finding 'Group' $sam $attr $val }
        }
    }
    $r.Dispose()
}

Write-Host "[*] OUs..." -ForegroundColor DarkGray
$s = Get-Searcher '(objectCategory=organizationalUnit)' $ouAttribs
if ($s) {
    $r = $s.FindAll()
    foreach ($entry in $r) {
        $name = Extract-Val $entry 'name'
        foreach ($attr in ($ouAttribs | Where-Object { $_ -ne 'name' })) {
            $val = Extract-Val $entry $attr
            if ($val -and -not (Is-Boring $val)) { Add-Finding 'OU' $name $attr $val }
        }
    }
    $r.Dispose()
}

Write-Host "[*] GPOs..." -ForegroundColor DarkGray
$s = Get-Searcher '(objectCategory=groupPolicyContainer)' $gpoAttribs
if ($s) {
    $r = $s.FindAll()
    foreach ($entry in $r) {
        $name = Extract-Val $entry 'displayName'
        foreach ($attr in ($gpoAttribs | Where-Object { $_ -ne 'displayName' })) {
            $val = Extract-Val $entry $attr
            if ($val -and -not (Is-Boring $val)) { Add-Finding 'GPO' $name $attr $val }
        }
    }
    $r.Dispose()
}

Write-Host "[*] Printers..." -ForegroundColor DarkGray
$s = Get-Searcher '(objectCategory=printQueue)' $printerAttribs
if ($s) {
    $r = $s.FindAll()
    foreach ($entry in $r) {
        $name = Extract-Val $entry 'printerName'
        foreach ($attr in ($printerAttribs | Where-Object { $_ -ne 'printerName' })) {
            $val = Extract-Val $entry $attr
            if ($val -and -not (Is-Boring $val)) { Add-Finding 'Printer' $name $attr $val }
        }
    }
    $r.Dispose()
}

Write-Host "[*] SMB shares..." -ForegroundColor DarkGray
$skipDescs = @('Remote Admin','Default share','Remote IPC','Printer Drivers','Logon server share','')
try {
    Get-CimInstance Win32_Share -ErrorAction Stop | ForEach-Object {
        $desc = $_.Description
        if ($desc -and $skipDescs -notcontains $desc.Trim() -and -not (Is-Boring $desc)) {
            Add-Finding 'SMB' $_.Name 'Description' $desc
        }
    }
} catch {
    Write-Host "  [-] SMB: $_" -ForegroundColor DarkGray
}

Write-Host ""

if ($findings.Count -eq 0) {
    Write-Host "No interesting strings found." -ForegroundColor Green
    exit 0
}

Write-Host "=== SmallStringsHunt ===" -ForegroundColor Cyan
Write-Host ""

$creds = $findings | Where-Object { $_.CredLike }
$other = $findings | Where-Object { -not $_.CredLike }

if ($creds) {
    Write-Host "[POTENTIAL CREDENTIALS]" -ForegroundColor Yellow
    foreach ($f in ($creds | Sort-Object Type, Object)) {
        Write-Host "  [$($f.Type.PadRight(8))] $($f.Object)" -ForegroundColor Yellow
        Write-Host "    $($f.Attr): $($f.Value)" -ForegroundColor White
    }
    Write-Host ""
}

$types = $other | Select-Object -ExpandProperty Type -Unique | Sort-Object
foreach ($type in $types) {
    Write-Host "[$type]" -ForegroundColor DarkCyan
    $other | Where-Object { $_.Type -eq $type } | Sort-Object Object | ForEach-Object {
        Write-Host "  $($_.Object) -> $($_.Attr)"
        Write-Host "    $($_.Value)"
    }
    Write-Host ""
}

Write-Host "Total: $($findings.Count) finding(s)  ($($creds.Count) potential cred(s))" -ForegroundColor DarkGray