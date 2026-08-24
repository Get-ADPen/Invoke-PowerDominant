<#
USAGE: 
Get-ChildItem HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer
Get-ChildItem HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer
#>

$HKLM = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated
$HKCU = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated

Write-Host "=== AlwaysInstallElevated Check ==="

if ($HKLM -eq 1) {
    Write-Host "[+] HKLM policy: Enabled"
} else {
    Write-Host "[-] HKLM policy: Disabled or not set"
}

if ($HKCU -eq 1) {
    Write-Host "[+] HKCU policy: Enabled"
} else {
    Write-Host "[-] HKCU policy: Disabled or not set"
}

if ($HKLM -eq 1 -and $HKCU -eq 1) {
    Write-Host ""
    Write-Host "[!] Finding: AlwaysInstallElevated is enabled."
    Write-Host "Meaning: Any MSI package installed through Windows Installer may run with elevated privileges."
    Write-Host "Recommendation: Disable the policy in both HKLM and HKCU unless it is required for managed software deployment."
}