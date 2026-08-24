$findings = [System.Collections.Generic.List[PSCustomObject]]::new()

$credPattern = [regex]'(?i)(?:password|passwd|pwd|secret|token|api[_.]?key|connectionstring|auth|credentials?)\s*[=:]\s*[''"]?([^\s''"><,\]{]{6,})'
$skipValues  = @('true','false','null','none','empty','changeme','your_password',
                 'placeholder','<password>','password','example','default','$env:',
                 '%password%','*','xxxxx')

function Add-Finding {
    param($Category, $Source, $Label, $Value, [string]$Context = '')
    $findings.Add([PSCustomObject]@{
        Category = $Category
        Source   = $Source
        Label    = $Label
        Value    = $Value
        Context  = $Context
    })
}

function Scan-FileForCreds {
    param([string]$Path, [string]$Source)
    try {
        $fi = [System.IO.FileInfo]::new($Path)
        if ($fi.Length -gt 512KB -or $fi.Length -eq 0) { return }
        $lines = [System.IO.File]::ReadAllLines($Path)
        $n = 0
        foreach ($line in $lines) {
            $n++
            $m = $credPattern.Match($line)
            if ($m.Success) {
                $val = $m.Groups[1].Value.Trim('"''`')
                if ($skipValues -contains $val.ToLower()) { continue }
                if ($val -match '^\$[A-Za-z]') { continue }
                if ($val.Length -lt 6) { continue }
                Add-Finding 'ContentScan' $Source "Line $n" $val ($line.Trim())
            }
        }
    } catch {}
}

function Read-FileLines {
    param([string]$Path, [int]$Max = 200)
    try {
        $lines = [System.IO.File]::ReadAllLines($Path)
        if ($lines.Count -gt $Max) { return $lines[0..($Max-1)] + @("... [truncated at $Max lines]") }
        return $lines
    } catch { return @() }
}

function Is-TextFile {
    param([string]$Path)
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path) | Select-Object -First 512
        return ($bytes -notcontains 0)
    } catch { return $false }
}

$users = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch '^(Public|Default.*|All Users)$' }

Write-Host "[*] PowerShell history..." -ForegroundColor DarkGray
foreach ($u in $users) {
    $hist = "$($u.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path $hist) {
        $lines = Read-FileLines $hist
        $lines | Where-Object { $_ -match '\S' } | ForEach-Object {
            Add-Finding 'PSHistory' $u.Name 'Command' $_ ''
        }
    }
}

Write-Host "[*] SSH artifacts..." -ForegroundColor DarkGray
$sshKeyNames = @('id_rsa','id_ed25519','id_ecdsa','id_dsa','id_rsa_old','*.pem','*.ppk','*.key')
foreach ($u in $users) {
    $sshDir = "$($u.FullName)\.ssh"
    if (-not (Test-Path $sshDir)) { continue }
    Get-ChildItem $sshDir -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $f = $_.FullName
        if ($_.Name -eq 'config') {
            Read-FileLines $f | Where-Object { $_ -match '\S' } |
                ForEach-Object { Add-Finding 'SSH' $u.Name 'config' $_ '' }
        } elseif ($_.Name -eq 'known_hosts' -or $_.Name -eq 'authorized_keys') {
            Add-Finding 'SSH' $u.Name $_.Name "[exists] $f" ''
        } elseif (Is-TextFile $f) {
            $firstLine = (Read-FileLines $f 1)[0]
            if ($firstLine -match 'PRIVATE KEY') {
                Add-Finding 'SSH' $u.Name "PrivateKey[$($_.Name)]" $f ''
            }
        }
    }
}

$sysSsh = 'C:\Windows\System32\OpenSSH'
if (Test-Path $sysSsh) {
    Get-ChildItem $sysSsh -Filter '*.key' -ErrorAction SilentlyContinue |
        ForEach-Object { Add-Finding 'SSH' 'SYSTEM' "HostKey" $_.FullName '' }
}

Write-Host "[*] Unattend / Sysprep..." -ForegroundColor DarkGray
$unattendPaths = @(
    'C:\unattend.xml','C:\autounattend.xml',
    'C:\Windows\system32\sysprep\unattend.xml',
    'C:\Windows\system32\sysprep\sysprep.xml',
    'C:\Windows\Panther\unattend.xml',
    'C:\Windows\Panther\Unattend\unattend.xml',
    'C:\Windows\setup\scripts\unattend.xml'
)
foreach ($p in $unattendPaths) {
    if (Test-Path $p) {
        $lines = Read-FileLines $p
        $lines | Where-Object { $_ -match '(?i)(password|username|autologon)' } |
            ForEach-Object { Add-Finding 'Unattend' $p 'Line' $_.Trim() '' }
    }
}

Write-Host "[*] Web configs..." -ForegroundColor DarkGray
$webRoots = @('C:\inetpub','C:\xampp','C:\wamp','C:\wamp64','C:\laragon','C:\AppServ')
$webFiles  = @('web.config','appsettings.json','appsettings.Development.json',
               'appsettings.Production.json','applicationHost.config','wp-config.php',
               'config.php','database.php','db.php','settings.py','database.yml',
               'secrets.yml','config.yml','parameters.yml','parameters.php')
foreach ($root in $webRoots) {
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem $root -Recurse -Include $webFiles -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -lt 512KB } |
        ForEach-Object { Scan-FileForCreds $_.FullName $_.FullName }
}

Write-Host "[*] .env files..." -ForegroundColor DarkGray
$envSearchRoots = @('C:\','D:\','C:\Users')
foreach ($root in $envSearchRoots) {
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem $root -Filter '.env*' -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -lt 128KB -and -not $_.PSIsContainer } |
        ForEach-Object {
            Read-FileLines $_.FullName | Where-Object { $_ -match '=' -and $_ -notmatch '^\s*#' } |
                ForEach-Object { Add-Finding 'EnvFile' $_.FullName 'Entry' $_.Trim() '' }
        }
}

Write-Host "[*] Credential XML (Export-Clixml)..." -ForegroundColor DarkGray
foreach ($u in $users) {
    Get-ChildItem $u.FullName -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -eq '.xml' -and $_.Name -match '(?i)(cred|pass|secret|auth)' -and $_.Length -lt 64KB } |
        ForEach-Object {
            $firstLine = (Read-FileLines $_.FullName 3) -join ' '
            if ($firstLine -match 'SecureString|PSCredential|Objs') {
                Add-Finding 'CredXML' $u.Name $_.Name "[PSCredential blob] $($_.FullName)" ''
            }
        }
}

Write-Host "[*] Cloud credentials..." -ForegroundColor DarkGray
foreach ($u in $users) {
    $awsCred = "$($u.FullName)\.aws\credentials"
    if (Test-Path $awsCred) {
        Read-FileLines $awsCred | Where-Object { $_ -match '\S' } |
            ForEach-Object { Add-Finding 'AWS' $u.Name 'credentials' $_.Trim() '' }
    }
    $awsConf = "$($u.FullName)\.aws\config"
    if (Test-Path $awsConf) {
        Add-Finding 'AWS' $u.Name 'config-exists' $awsConf ''
    }
    $azureDir = "$($u.FullName)\.azure"
    if (Test-Path $azureDir) {
        Get-ChildItem $azureDir -Filter '*.json' -Force -ErrorAction SilentlyContinue |
            ForEach-Object { Scan-FileForCreds $_.FullName "Azure[$($u.Name)]" }
    }
    $gcpCred = "$($u.FullName)\AppData\Roaming\gcloud\credentials.db"
    if (Test-Path $gcpCred) { Add-Finding 'GCP' $u.Name 'credentials.db' $gcpCred '' }
    $gcpAdc = "$($u.FullName)\AppData\Roaming\gcloud\application_default_credentials.json"
    if (Test-Path $gcpAdc) { Scan-FileForCreds $gcpAdc "GCP[$($u.Name)]" }
}

Write-Host "[*] Git configs (embedded creds)..." -ForegroundColor DarkGray
foreach ($u in $users) {
    $gitConf = "$($u.FullName)\.gitconfig"
    if (Test-Path $gitConf) {
        Read-FileLines $gitConf | Where-Object { $_ -match '://.+:.+@' } |
            ForEach-Object { Add-Finding 'Git' $u.Name '.gitconfig' $_.Trim() '' }
    }
    Get-ChildItem $u.FullName -Recurse -Force -ErrorAction SilentlyContinue -Filter 'config' |
        Where-Object { $_.DirectoryName -match '\\.git$' -and $_.Length -lt 32KB } |
        ForEach-Object {
            Read-FileLines $_.FullName | Where-Object { $_ -match '://.+:.+@' } |
                ForEach-Object { Add-Finding 'Git' $u.Name $_.DirectoryName $_.Trim() '' }
        }
}

Write-Host "[*] Known secret file names..." -ForegroundColor DarkGray
$secretNames = @(
    'passwords.txt','password.txt','creds.txt','credentials.txt','pass.txt',
    'logins.txt','secrets.txt','keys.txt','tokens.txt','accounts.txt',
    'id_rsa','*.kdbx','*.kdb','*.pfx','*.p12','*.jks','*.keystore'
)
$searchDrives = @('C:\','D:\')
foreach ($drive in $searchDrives) {
    if (-not (Test-Path $drive)) { continue }
    foreach ($pattern in $secretNames) {
        Get-ChildItem $drive -Filter $pattern -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer -and $_.Length -lt 1MB } |
            ForEach-Object {
                if ($_.Extension -in @('.txt','.csv','')) {
                    Read-FileLines $_.FullName 50 | Where-Object { $_ -match '\S' } |
                        ForEach-Object { Add-Finding 'SecretFile' $_.FullName 'Line' $_.Trim() '' }
                } else {
                    Add-Finding 'SecretFile' $_.DirectoryName $_.Name "[binary/keystore] $($_.FullName)" ''
                }
            }
    }
}

Write-Host "[*] Script content scan (.ps1/.bat/.cmd)..." -ForegroundColor DarkGray
foreach ($u in $users) {
    Get-ChildItem $u.FullName -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in @('.ps1','.bat','.cmd','.py','.php','.rb') -and $_.Length -lt 256KB } |
        ForEach-Object { Scan-FileForCreds $_.FullName $_.FullName }
}

$scriptPaths = @('C:\scripts','C:\tools','C:\admin','C:\backup','C:\deploy','C:\automation')
foreach ($sp in $scriptPaths) {
    if (-not (Test-Path $sp)) { continue }
    Get-ChildItem $sp -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in @('.ps1','.bat','.cmd','.py','.php','.rb','.conf','.cfg','.ini') -and $_.Length -lt 256KB } |
        ForEach-Object { Scan-FileForCreds $_.FullName $_.FullName }
}

Write-Host ""

if ($findings.Count -eq 0) {
    Write-Host "Nothing found." -ForegroundColor Green
    exit 0
}

Write-Host "=== HistoryAndSecretsSweep ===" -ForegroundColor Cyan
Write-Host ""

$priority = @('SSH','Unattend','CredXML','SecretFile','AWS','GCP','EnvFile')
$high     = $findings | Where-Object { $_.Category -in $priority }
$hist     = $findings | Where-Object { $_.Category -eq 'PSHistory' }
$web      = $findings | Where-Object { $_.Category -in @('ContentScan','Git') }

if ($high) {
    Write-Host "[HIGH VALUE]" -ForegroundColor Yellow
    foreach ($f in ($high | Sort-Object Category, Source)) {
        Write-Host "  [$($f.Category.PadRight(10))] $($f.Source)" -ForegroundColor Yellow
        Write-Host "    $($f.Label): $($f.Value)"
    }
    Write-Host ""
}

if ($hist) {
    Write-Host "[POWERSHELL HISTORY]" -ForegroundColor Cyan
    $byUser = $hist | Group-Object Source
    foreach ($g in $byUser) {
        Write-Host "  User: $($g.Name)" -ForegroundColor White
        $g.Group | ForEach-Object { Write-Host "    $($_.Value)" }
    }
    Write-Host ""
}

if ($web) {
    Write-Host "[REVIEW - Content Scan / Git]" -ForegroundColor Magenta
    foreach ($f in ($web | Sort-Object Source)) {
        Write-Host "  $($f.Source)"
        Write-Host "    $($f.Label): $($f.Value)"
        if ($f.Context -and $f.Context -ne $f.Value) {
            Write-Host "    >> $($f.Context)" -ForegroundColor DarkGray
        }
    }
    Write-Host ""
}

$hc  = $high.Count
$hsc = $hist.Count
$wc  = $web.Count
Write-Host "Total: $($findings.Count) finding(s)  (HighValue:$hc  History:$hsc  Review:$wc)" -ForegroundColor DarkGray