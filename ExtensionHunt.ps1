param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Extensions
)

$extList = $Extensions -split "," | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ -ne "" }

if ($extList.Count -eq 0) {
    Write-Error "No extensions provided."
    exit 1
}

if ($extList.Count -gt 5) {
    Write-Error "Maximum 5 extensions allowed. You provided $($extList.Count)."
    exit 1
}

foreach ($ext in $extList) {
    if ($ext -notmatch "^\.[a-zA-Z0-9]+$") {
        Write-Error "Invalid extension format: '$ext'. Use dot notation e.g. .ini"
        exit 1
    }
}

$drives = Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Root

$separator = "=" * 60
$results = @{}
foreach ($ext in $extList) { $results[$ext] = [System.Collections.Generic.List[string]]::new() }

Write-Output ""
Write-Output $separator
Write-Output "  ExtensionHunt"
Write-Output "  Target Extensions : $($extList -join ', ')"
Write-Output "  Scanning Drives   : $($drives -join ', ')"
Write-Output $separator

foreach ($drive in $drives) {
    Write-Output "`n[*] Scanning $drive ..."

    Get-ChildItem -Path $drive -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object {
            -not $_.PSIsContainer -and
            $extList -contains $_.Extension.ToLower()
        } |
        ForEach-Object {
            $ext = $_.Extension.ToLower()
            $results[$ext].Add($_.FullName)
            Write-Output "  [+] $($_.FullName)"
        }
}

Write-Output ""
Write-Output $separator
Write-Output "  SUMMARY"
Write-Output $separator

$total = 0
foreach ($ext in $extList) {
    $count = $results[$ext].Count
    $total += $count
    Write-Output "  $ext`t: $count file(s) found"
}

Write-Output ""
Write-Output "  Total : $total file(s) across $($drives.Count) drive(s)"
Write-Output $separator