param(
    [Parameter(Mandatory=$true)]
    [string]$Target,

    [int]$Timeout = 500,
    [int]$Retries = 1,
    [int]$Threads = 100,
    [string]$OutputFile = ""
)

function Get-IPRange {
    param([string]$CIDR)

    if ($CIDR -notmatch '^(\d+\.\d+\.\d+\.\d+)/(\d+)$') {
        return $null
    }

    $ip = $matches[1]
    $prefix = [int]$matches[2]

    $ipParts = $ip.Split('.') | ForEach-Object { [uint32]$_ }
    $ipInt = ($ipParts[0] -shl 24) -bor ($ipParts[1] -shl 16) -bor ($ipParts[2] -shl 8) -bor $ipParts[3]

    $mask = [uint32]([math]::Pow(2,32) - [math]::Pow(2,(32 - $prefix)))
    $network = $ipInt -band $mask
    $broadcast = $network + ([uint32]([math]::Pow(2,(32 - $prefix)) - 1))

    if ($prefix -eq 32) {
        return @($ip)
    }

    if ($prefix -eq 31) {
        return @(
            "{0}.{1}.{2}.{3}" -f (($network -shr 24) -band 0xFF), (($network -shr 16) -band 0xFF), (($network -shr 8) -band 0xFF), ($network -band 0xFF),
            "{0}.{1}.{2}.{3}" -f (($broadcast -shr 24) -band 0xFF), (($broadcast -shr 16) -band 0xFF), (($broadcast -shr 8) -band 0xFF), ($broadcast -band 0xFF)
        )
    }

    $ips = @()
    for ($i = $network + 1; $i -lt $broadcast; $i++) {
        $ips += "{0}.{1}.{2}.{3}" -f (($i -shr 24) -band 0xFF), (($i -shr 16) -band 0xFF), (($i -shr 8) -band 0xFF), ($i -band 0xFF)
    }

    return $ips
}

function Get-DomainInfo {
    param([string]$IP)

    $out = [PSCustomObject]@{ Hostname = "N/A"; Domain = "N/A" }

    try {
        $dnsEntry = [System.Net.Dns]::GetHostEntry($IP)
        if ($dnsEntry.HostName) { $out.Hostname = $dnsEntry.HostName }
    } catch {}

    try {
        $rootDSE = [ADSI]"LDAP://$IP/RootDSE"
        $ncName = $rootDSE.Properties["defaultNamingContext"][0]
        if ($ncName) {
            $out.Domain = ($ncName -replace 'DC=','' -replace ',','.')
        }
    } catch {}

    return $out
}

$ports = 20,21,22,23,25,42,49,53,67,68,69,79,80,81,88,102,110,111,113,119,123,135,137,138,139,143,161,162,177,179,199,201,264,363,389,407,443,445,464,465,497,500,512,513,514,515,523,524,540,548,554,587,593,623,626,631,636,646,691,860,873,902,903,989,990,993,995,1025,1026,1027,1028,1029,1080,1099,1177,1194,1234,1311,1352,1433,1434,1521,1720,1723,1741,1755,1812,1813,1863,1900,1935,2000,2049,2100,2179,2181,2375,2376,2379,2380,2401,2483,2484,3128,3260,3268,3269,3283,3299,3306,3389,3478,3690,3702,4045,4369,4500,4786,4840,4848,5000,5001,5060,5061,5093,5222,5351,5353,5357,5432,5555,5601,5666,5672,5683,5900,5901,5938,5984,5985,5986,6000,6379,6443,6660,6661,6665,6666,6667,6668,6669,6697,7001,7077,7199,7443,7474,7687,8000,8008,8009,8080,8081,8088,8089,8090,8091,8140,8161,8172,8200,8300,8333,8443,8500,8530,8531,8686,8888,9000,9042,9043,9090,9092,9100,9160,9200,9300,9389,9418,9999,10000,10250,10255,11211,15672,17185,20000,27017,27018,28017,32400,44818,47001,49152,49153,49154,49155,49156,49157,50000,50030,50060,50070,50075,50090,54328

$ips = Get-IPRange -CIDR $Target

if (-not $ips) {
    Write-Host "Invalid CIDR notation. Use format: 192.168.1.0/24"
    exit
}

$jobs = foreach ($ip in $ips) { foreach ($port in $ports) { [PSCustomObject]@{ IP = $ip; Port = $port } } }

$scriptBlock = {
    param($IP, $Port, $Timeout, $Retries)
    for ($r = 0; $r -le $Retries; $r++) {
        $tcp = $null
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $iar = $tcp.BeginConnect($IP, $Port, $null, $null)
            $wait = $iar.AsyncWaitHandle.WaitOne($Timeout, $false)
            if ($wait -and $tcp.Connected) {
                $tcp.EndConnect($iar)
                return "$IP`:$Port"
            }
        } catch {}
        finally {
            if ($tcp) { $tcp.Close() }
        }
    }
    return $null
}

$pool = [runspacefactory]::CreateRunspacePool(1, $Threads)
$pool.Open()
$runspaces = @()

foreach ($job in $jobs) {
    $ps = [powershell]::Create()
    $ps.RunspacePool = $pool
    [void]$ps.AddScript($scriptBlock).AddArgument($job.IP).AddArgument($job.Port).AddArgument($Timeout).AddArgument($Retries)
    $runspaces += [PSCustomObject]@{ Pipe = $ps; Handle = $ps.BeginInvoke() }
}

$openResults = @()

foreach ($r in $runspaces) {
    $out = $r.Pipe.EndInvoke($r.Handle)
    $r.Pipe.Dispose()
    if ($out) {
        $out
        $openResults += $out
    }
}

$pool.Close()
$pool.Dispose()

$hostGroups = $openResults | ForEach-Object { ($_ -split ':')[0] } | Sort-Object -Unique

if ($hostGroups.Count -gt 0) {
    ""
    "--- host info ---"
    foreach ($h in $hostGroups) {
        $info = Get-DomainInfo -IP $h
        "$h  hostname=$($info.Hostname)  domain=$($info.Domain)"
    }
}

if ($OutputFile -ne "") {
    $openResults | ForEach-Object {
        $parts = $_ -split ':'
        [PSCustomObject]@{ IP = $parts[0]; Port = $parts[1] }
    } | Export-Csv -NoTypeInformation -Path $OutputFile
}