$ErrorActionPreference = 'SilentlyContinue'
Set-StrictMode -Off

$highInterestPublishers = @(
    'oracle','java','apache','eclipse','jetbrains','jboss','wildfly',
    'glassfish','tomcat','nginx','mysql','postgresql','mariadb','mongodb',
    'redis','elasticsearch','xampp','wamp','bitnami','filezilla','openssl',
    'python','ruby','perl','php','node','npm','git','putty','winscp',
    'openvpn','wireshark','nmap','7-zip','winrar','notepad++','sublime',
    'vscode','visual studio code'
)

$highInterestNames = @(
    'java','jre','jdk','glassfish','tomcat','jboss','wildfly','weblogic',
    'websphere','apache http','apache tomcat','xampp','wamp','laragon',
    'mysql','mariadb','postgresql','mongodb','redis','sqlite',
    'elasticsearch','kibana','logstash','jenkins','nexus','sonatype',
    'openssl','stunnel','filezilla server','winscp','openvpn',
    'python','ruby','perl','php','nodejs','node.js',
    'putty','mobaxterm','kitty','winscp',
    'git','subversion','svn','mercurial',
    'notepad++','sublime text','atom','brackets',
    'wireshark','nmap','npcap','winpcap',
    '7-zip','winrar','winzip',
    'vmware','virtualbox','vagrant','docker',
    'oracle','sql server express','sql server',
    'IIS','internet information'
)

$msPatterns = @(
    '^Microsoft','^Windows','^MS ','^Office ','^Visual C\+\+','^Visual Studio',
    '^\.NET','^PowerShell','^Xbox','^OneDrive','^Teams','^Edge','^Defender',
    '^Security Intelligence','Update for Windows','Hotfix','Service Pack',
    'KB\d{6,}','WMF ','Language Pack','MUI Pack','^WinPE'
)

$portablePaths = @(
    @{ Path = 'C:\glassfish4';           Label = 'GlassFish'   },
    @{ Path = 'C:\glassfish5';           Label = 'GlassFish'   },
    @{ Path = 'C:\glassfish6';           Label = 'GlassFish'   },
    @{ Path = 'C:\tomcat';               Label = 'Tomcat'       },
    @{ Path = 'C:\apache-tomcat*';       Label = 'Tomcat'       },
    @{ Path = 'C:\xampp';                Label = 'XAMPP'        },
    @{ Path = 'C:\wamp';                 Label = 'WAMP'         },
    @{ Path = 'C:\wamp64';               Label = 'WAMP64'       },
    @{ Path = 'C:\laragon';              Label = 'Laragon'      },
    @{ Path = 'C:\nginx*';               Label = 'nginx'        },
    @{ Path = 'C:\php*';                 Label = 'PHP'          },
    @{ Path = 'C:\Python*';              Label = 'Python'       },
    @{ Path = 'C:\Ruby*';               Label = 'Ruby'         },
    @{ Path = 'C:\Perl*';               Label = 'Perl'         },
    @{ Path = 'C:\node*';               Label = 'Node.js'      },
    @{ Path = 'C:\jenkins';             Label = 'Jenkins'      },
    @{ Path = 'C:\sonatype-work';       Label = 'Sonatype'     },
    @{ Path = 'C:\nexus*';              Label = 'Nexus'        },
    @{ Path = 'C:\elasticsearch*';      Label = 'Elasticsearch'},
    @{ Path = 'C:\Program Files\Java*'; Label = 'Java'         },
    @{ Path = 'C:\Program Files (x86)\Java*'; Label = 'Java'  },
    @{ Path = 'C:\jdk*';               Label = 'JDK'          },
    @{ Path = 'C:\jre*';               Label = 'JRE'          },
    @{ Path = 'C:\redis*';             Label = 'Redis'         },
    @{ Path = 'C:\mongodb*';           Label = 'MongoDB'       },
    @{ Path = 'C:\mysql*';             Label = 'MySQL'         },
    @{ Path = 'C:\pgsql*';            Label = 'PostgreSQL'    },
    @{ Path = 'C:\postgresql*';       Label = 'PostgreSQL'    }
)

$portableBinaries = @{
    'GlassFish'    = @('bin\asadmin.bat','modules\glassfish.jar')
    'Tomcat'       = @('bin\catalina.bat','bin\catalina.sh')
    'XAMPP'        = @('xampp-control.exe')
    'nginx'        = @('nginx.exe')
    'PHP'          = @('php.exe')
    'Python'       = @('python.exe')
    'Ruby'         = @('bin\ruby.exe')
    'Perl'         = @('bin\perl.exe')
    'Node.js'      = @('node.exe')
    'Jenkins'      = @('jenkins.exe','jenkins.war')
    'MySQL'        = @('bin\mysqld.exe','bin\mysql.exe')
    'PostgreSQL'   = @('bin\postgres.exe','bin\pg_ctl.exe')
    'MongoDB'      = @('bin\mongod.exe')
    'Redis'        = @('redis-server.exe')
    'Elasticsearch'= @('bin\elasticsearch.bat')
}

function Get-FileVer {
    param([string]$Path)
    try {
        $vi = (Get-Item $Path -ErrorAction Stop).VersionInfo
        $v  = $vi.ProductVersion
        if ([string]::IsNullOrWhiteSpace($v) -or $v -eq '0.0.0.0') {
            $v = $vi.FileVersion
        }
        if ([string]::IsNullOrWhiteSpace($v) -or $v -eq '0.0.0.0') { return $null }
        return $v.Trim()
    } catch { return $null }
}

function Is-Microsoft {
    param([string]$Name, [string]$Publisher)
    foreach ($p in $msPatterns) {
        if ($Name -match $p) { return $true }
        if ($Publisher -match $p) { return $true }
    }
    if ($Publisher -match '(?i)microsoft') { return $true }
    return $false
}

function Is-HighInterest {
    param([string]$Name, [string]$Publisher)
    $nl = $Name.ToLower(); $pl = $Publisher.ToLower()
    foreach ($h in $highInterestNames)      { if ($nl -match [regex]::Escape($h)) { return $true } }
    foreach ($h in $highInterestPublishers) { if ($pl -match [regex]::Escape($h)) { return $true } }
    return $false
}

function Read-UninstallKey {
    param([string]$Base)
    $out = [System.Collections.Generic.List[PSCustomObject]]::new()
    if (-not (Test-Path $Base)) { return $out }
    Get-ChildItem $Base -ErrorAction SilentlyContinue | ForEach-Object {
        $p    = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        $name = $p.DisplayName
        $pub  = "$($p.Publisher)"
        $ver  = "$($p.DisplayVersion)"
        if ([string]::IsNullOrWhiteSpace($name)) { return }
        if (Is-Microsoft $name $pub) { return }
        if ([string]::IsNullOrWhiteSpace($ver)) { $ver = 'unknown' }
        $loc  = "$($p.InstallLocation)"
        $src  = "$($p.InstallSource)"
        $date = "$($p.InstallDate)"
        $out.Add([PSCustomObject]@{
            Name      = $name.Trim()
            Publisher = $pub.Trim()
            Version   = $ver.Trim()
            Location  = $loc.Trim()
            Date      = $date.Trim()
            Arch      = if ($Base -match 'WOW6432') { 'x86' } else { 'x64' }
            Source    = 'Registry'
        })
    }
    return $out
}

$regEntries = [System.Collections.Generic.List[PSCustomObject]]::new()

$bases = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
)

Write-Host "[*] Registry (Uninstall keys)..." -ForegroundColor DarkGray
foreach ($b in $bases) {
    foreach ($r in (Read-UninstallKey $b)) { $regEntries.Add($r) }
}

$seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$deduped = $regEntries | Where-Object { $seen.Add("$($_.Name)|$($_.Publisher)") }

$highReg  = $deduped | Where-Object { Is-HighInterest $_.Name $_.Publisher } | Sort-Object Name
$otherReg = $deduped | Where-Object { -not (Is-HighInterest $_.Name $_.Publisher) } | Sort-Object Name

Write-Host "[*] Portable path scan..." -ForegroundColor DarkGray
$portableFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($entry in $portablePaths) {
    $resolved = Resolve-Path $entry.Path -ErrorAction SilentlyContinue
    if (-not $resolved) { continue }
    foreach ($dir in $resolved) {
        if (-not (Test-Path $dir.Path -PathType Container)) { continue }
        $label   = $entry.Label
        $ver     = $null
        $binHit  = $null
        if ($portableBinaries.ContainsKey($label)) {
            foreach ($rel in $portableBinaries[$label]) {
                $full = Join-Path $dir.Path $rel
                if (Test-Path $full -PathType Leaf) {
                    $binHit = $full
                    $v = Get-FileVer $full
                    if ($v) { $ver = $v; break }
                }
            }
        }
        if (-not $ver) {
            Get-ChildItem $dir.Path -Recurse -Include '*.exe','*.jar','*.dll' -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -gt 0 } |
                Select-Object -First 5 |
                ForEach-Object {
                    if (-not $ver) {
                        $v = Get-FileVer $_.FullName
                        if ($v) { $ver = $v; $binHit = $_.FullName }
                    }
                }
        }
        $alreadyInReg = $deduped | Where-Object { $_.Location -and ($dir.Path -like "*$($_.Location)*" -or $_.Location -like "*$($dir.Path)*") }
        $portableFindings.Add([PSCustomObject]@{
            Name     = $label
            Path     = $dir.Path
            Version  = if ($ver) { $ver } else { 'unknown' }
            Binary   = if ($binHit) { $binHit } else { 'n/a' }
            InReg    = ($alreadyInReg.Count -gt 0)
        })
    }
}

Write-Host ""
Write-Host "=== NonDefaultHunt ===" -ForegroundColor Cyan
Write-Host ""

if ($highReg) {
    Write-Host "[HIGH INTEREST]" -ForegroundColor Yellow
    foreach ($a in $highReg) {
        $loc = if ($a.Location) { "  Location : $($a.Location)" } else { '' }
        Write-Host "  $($a.Name)" -ForegroundColor Yellow
        Write-Host "    Publisher : $($a.Publisher)"
        Write-Host "    Version   : $($a.Version)  [$($a.Arch)]"
        if ($a.Date) { Write-Host "    Installed : $($a.Date)" }
        if ($loc)    { Write-Host $loc }
    }
    Write-Host ""
}

if ($otherReg) {
    Write-Host "[THIRD PARTY]" -ForegroundColor Cyan
    foreach ($a in $otherReg) {
        Write-Host "  $($a.Name)  [$($a.Version)]  $($a.Publisher)"
    }
    Write-Host ""
}

$newPortable = $portableFindings | Where-Object { -not $_.InReg }
$dupPortable = $portableFindings | Where-Object { $_.InReg }

if ($newPortable) {
    Write-Host "[PORTABLE - not in registry]" -ForegroundColor Magenta
    foreach ($p in $newPortable) {
        Write-Host "  $($p.Name)" -ForegroundColor Magenta
        Write-Host "    Path    : $($p.Path)"
        Write-Host "    Version : $($p.Version)"
        if ($p.Binary -ne 'n/a') { Write-Host "    Binary  : $($p.Binary)" }
    }
    Write-Host ""
}

if ($dupPortable) {
    Write-Host "[PORTABLE - also in registry]" -ForegroundColor DarkGray
    foreach ($p in $dupPortable) {
        Write-Host "  $($p.Name)  $($p.Path)  [$($p.Version)]"
    }
    Write-Host ""
}

$total = $deduped.Count + $portableFindings.Count
Write-Host "Total: $total  (HighInterest:$($highReg.Count)  ThirdParty:$($otherReg.Count)  Portable:$($portableFindings.Count))" -ForegroundColor DarkGray