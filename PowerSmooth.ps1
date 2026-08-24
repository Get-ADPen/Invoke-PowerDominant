$Line = "=" * 60

function Section($title) {
    Write-Output "`n$Line"
    Write-Output "  $title"
    Write-Output $Line
}

Section "SYSTEM INFO"
$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
Write-Output "Hostname     : $($cs.Name)"
Write-Output "Domain       : $($cs.Domain)"
Write-Output "OS           : $($os.Caption) $($os.Version)"
Write-Output "Architecture : $($os.OSArchitecture)"
Write-Output "Current User : $env:USERNAME"
Write-Output "Logon Server : $env:LOGONSERVER"

Section "CURRENT USER PRIVILEGES"
whoami /all

Section "LOCAL USERS"
Get-LocalUser | Format-Table Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet -AutoSize

Section "LOCAL GROUPS"
Get-LocalGroup | Format-Table Name, Description -AutoSize

Section "LOCAL ADMINS"
net localgroup administrators

Section "DOMAIN USERS (if domain-joined)"
try { net user /domain 2>&1 } catch { Write-Output "Not domain-joined or access denied" }

Section "DOMAIN ADMINS (if domain-joined)"
try { net group "Domain Admins" /domain 2>&1 } catch { Write-Output "Not domain-joined or access denied" }

Section "DOMAIN GROUPS (if domain-joined)"
try { net group /domain 2>&1 } catch { Write-Output "Not domain-joined or access denied" }

Section "DOMAIN INFO"
try {
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    Write-Output "Domain Name  : $($domain.Name)"
    Write-Output "Forest       : $($domain.Forest)"
    Write-Output "DCs          :"
    $domain.DomainControllers | ForEach-Object { Write-Output "  $_" }
} catch { Write-Output "Not domain-joined or ADSI unavailable" }

Section "NETWORK INTERFACES"
Get-NetIPAddress | Where-Object { $_.AddressFamily -eq "IPv4" } |
    Format-Table InterfaceAlias, IPAddress, PrefixLength -AutoSize

Section "ROUTING TABLE"
Get-NetRoute | Where-Object { $_.AddressFamily -eq "IPv4" } |
    Format-Table DestinationPrefix, NextHop, RouteMetric, InterfaceAlias -AutoSize

Section "ACTIVE CONNECTIONS"
netstat -ano

Section "DNS CACHE"
Get-DnsClientCache | Format-Table Entry, RecordName, Data -AutoSize

Section "ARP TABLE"
arp -a

Section "HOSTS FILE"
Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" |
    Where-Object { $_ -notmatch "^#" -and $_.Trim() -ne "" }

Section "NETWORK SHARES"
net share

Section "SMB SHARES"
Get-SmbShare 2>$null | Format-Table Name, Path, Description -AutoSize

Section "FIREWALL STATUS"
netsh advfirewall show allprofiles state

Section "FIREWALL RULES (Allow Inbound)"
Get-NetFirewallRule | Where-Object {
    $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" -and $_.Enabled -eq "True"
} | Select-Object DisplayName, Profile | Format-Table -AutoSize

Section "RUNNING PROCESSES"
Get-CimInstance Win32_Process |
    Select-Object ProcessId, Name, ExecutablePath,
        @{N="Owner";E={ try { $_.GetOwner().User } catch { "N/A" } }} |
    Sort-Object Name | Format-Table -AutoSize

Section "SERVICES"
Get-CimInstance Win32_Service |
    Select-Object Name, State, StartMode, PathName, StartName |
    Sort-Object State, Name | Format-Table -AutoSize

Section "SERVICES WITH UNQUOTED PATHS"
Get-CimInstance Win32_Service |
    Where-Object {
        $_.PathName -notmatch '^"' -and
        $_.PathName -match ' ' -and
        $_.PathName -notmatch '^C:\\Windows'
    } |
    Select-Object Name, PathName, StartName | Format-Table -AutoSize

Section "SERVICES WITH WEAK PERMISSIONS (current user writable)"
Get-CimInstance Win32_Service | ForEach-Object {
    $path = ($_.PathName -split '"' | Where-Object { $_ -match '\.' })[0]
    if ($path) {
        $path = $path.Trim()
        try {
            $acl = Get-Acl $path -ErrorAction SilentlyContinue
            $writable = $acl.Access | Where-Object {
                $_.IdentityReference -match "$env:USERNAME|Everyone|Users|Authenticated" -and
                $_.FileSystemRights -match "Write|Modify|FullControl"
            }
            if ($writable) {
                Write-Output "Service: $($_.Name) | Path: $path"
            }
        } catch {}
    }
}

Section "SCHEDULED TASKS"
Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch "^\\Microsoft" } |
    Select-Object TaskName, TaskPath, State,
        @{N="RunAs";E={ $_.Principal.UserId }} |
    Format-Table -AutoSize

Section "SCHEDULED TASK ACTIONS (non-Microsoft)"
Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch "^\\Microsoft" } | ForEach-Object {
    $t = $_
    $t.Actions | ForEach-Object {
        [PSCustomObject]@{
            Task    = $t.TaskName
            Execute = $_.Execute
            Args    = $_.Arguments
        }
    }
} | Format-Table -AutoSize

Section "INSTALLED SOFTWARE (Registry)"
$paths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$paths | ForEach-Object {
    Get-ItemProperty $_ -ErrorAction SilentlyContinue
} | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Where-Object { $_.DisplayName } | Sort-Object DisplayName | Format-Table -AutoSize

Section "INSTALLED HOTFIXES / PATCHES"
Get-HotFix | Sort-Object InstalledOn -Descending | Format-Table HotFixID, Description, InstalledOn -AutoSize

Section "ENVIRONMENT VARIABLES"
Get-ChildItem Env: | Format-Table Name, Value -AutoSize

Section "AUTORUN REGISTRY KEYS"
$runKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)
foreach ($key in $runKeys) {
    Write-Output "`n[$key]"
    Get-ItemProperty $key -ErrorAction SilentlyContinue |
        Select-Object * -ExcludeProperty PS* | Format-List
}

Section "ALWAYS INSTALL ELEVATED CHECK"
$hklm = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated
$hkcu = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated
Write-Output "HKLM AlwaysInstallElevated: $hklm"
Write-Output "HKCU AlwaysInstallElevated: $hkcu"
if ($hklm -eq 1 -and $hkcu -eq 1) { Write-Output "[!] AlwaysInstallElevated is ENABLED - MSI privesc possible" }

Section "CREDENTIAL MANAGER"
cmdkey /list

Section "DPAPI MASTER KEYS"
$mpaths = @(
    "$env:APPDATA\Microsoft\Protect",
    "$env:LOCALAPPDATA\Microsoft\Protect"
)
foreach ($p in $mpaths) {
    if (Test-Path $p) {
        Get-ChildItem -Recurse $p -ErrorAction SilentlyContinue | Format-Table FullName -AutoSize
    }
}

Section "INTERESTING FILES - USER PROFILE"
$targets = @(
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Downloads",
    "$env:APPDATA",
    "$env:LOCALAPPDATA"
)
foreach ($t in $targets) {
    if (Test-Path $t) {
        Get-ChildItem $t -ErrorAction SilentlyContinue -Recurse -Depth 2 |
            Where-Object {
                $_.Name -match "password|passwd|cred|secret|key|token|config|\.kdbx|\.xml|\.ini|\.txt|\.cfg|id_rsa|\.pem" -and
                -not $_.PSIsContainer
            } | Select-Object FullName, LastWriteTime | Format-Table -AutoSize
    }
}

Section "INTERESTING FILES - SYSTEM PATHS"
$systargets = @(
    "C:\inetpub",
    "C:\xampp",
    "C:\wamp",
    "C:\Apache",
    "C:\nginx",
    "C:\ProgramData",
    "C:\Program Files",
    "C:\Program Files (x86)"
)
foreach ($t in $systargets) {
    if (Test-Path $t) {
        Get-ChildItem $t -ErrorAction SilentlyContinue -Recurse -Depth 3 |
            Where-Object {
                $_.Name -match "password|passwd|cred|secret|\.config|web\.config|\.xml|\.ini|\.env|\.bak|\.old" -and
                -not $_.PSIsContainer
            } | Select-Object FullName, LastWriteTime | Format-Table -AutoSize
    }
}

Section "POWERSHELL HISTORY"
$histPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $histPath) { Get-Content $histPath } else { Write-Output "No PS history found" }

Section "RECENT COMMANDS (cmd history via doskey)"
doskey /history 2>$null

Section "WRITABLE DIRECTORIES IN PATH"
($env:PATH -split ";") | ForEach-Object {
    $p = $_.Trim()
    if ($p -and (Test-Path $p)) {
        try {
            $null = [System.IO.File]::Create("$p\_test_write_$([guid]::NewGuid()).tmp")
            Write-Output "[WRITABLE] $p"
        } catch {}
    }
}

Section "ANTIVIRUS / SECURITY PRODUCTS"
Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
    Select-Object DisplayName, productState, pathToSignedProductExe | Format-Table -AutoSize

Get-CimInstance Win32_Process | Where-Object {
    $_.Name -match "MsMpEng|defender|cbdefense|cylance|crowdstrike|sentinel|tanium|carbon|elastic|falcon"
} | Select-Object Name, ProcessId, ExecutablePath | Format-Table -AutoSize

Section "LAPS CHECK"
try {
    Get-AdComputer $env:COMPUTERNAME -Properties ms-Mcs-AdmPwd 2>$null |
        Select-Object Name, "ms-Mcs-AdmPwd" | Format-Table -AutoSize
} catch {}
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -ErrorAction SilentlyContinue

Section "WSUS / UPDATE SERVER"
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue |
    Select-Object WUServer, WUStatusServer | Format-List

Section "DRIVE INFO"
Get-PSDrive -PSProvider FileSystem | Format-Table Name, Root, Used, Free -AutoSize

Section "DONE"
Write-Output "Enumeration complete."