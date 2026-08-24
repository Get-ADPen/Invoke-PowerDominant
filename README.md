<p align="center">
    <picture>
        <img src="./Photos/power.png" alt="PowerDominant" width='200'/>
    </picture>
</p>

<div align="center">
<h1>Invoke-PowerDominant</h1>

Custom offensive PowerShell collection for internal Windows enumeration, privilege escalation, AD attacks, and evasion.
<p></div>

![PowerShell Language](https://img.shields.io/badge/language-powershell-blue.svg)

<p align="center">
  <a href="https://github.com/d1pakda5/PowerShell-for-Pentesters">101</a> •
  <a href="#">Exec</a>
</p>

- _ActiveProcessHunt.ps1_ `::` Finds writable service binaries, scheduled tasks, and startup items via ACL testing. Catches FileWrite, DirWrite, and Unquoted service paths. Use `--strict` to include System32/Program Files.

- _AMSI-Bypass-Revshell.ps1_ `::` Compact AMSI bypass combined with a reverse shell payload. Drop and run when AMSI is blocking your other scripts.

- _Azure-CredsExtract.ps1_ `::` Extracts Azure credentials and tokens from the current session, local files, and environment. Useful post-compromise on cloud-joined or hybrid machines.

- _DoIHaveDPAPIOnMe.ps1_ `::` Hunts DPAPI artifacts across all local users: MasterKeys, Credential blobs, Vault files, and browser Login Data. Outputs prioritized download list with matching Impacket-DPAPI commands.

- _DotMSI-Hunt.ps1_ `::` Locates MSI installer files left on disk. Leftover installers sometimes carry credentials or reveal software versions not visible in the registry.

- _Enable-AllPrivilege.ps1_ `::` Enables all currently disabled token privileges in one shot. Run before privilege-dependent exploits.

- _Enable-Privilege.ps1_ `::` Enables a single named token privilege. Lighter alternative to Enable-AllPrivilege when targeting a specific right like SeImpersonatePrivilege.

- _ExtensionHunt.ps1_ `::` Recursively searches for files by extension across specified paths. Feed it `.config`, `.xml`, `.kdbx`, `.pfx` or anything else you're hunting.

- _Find-AVExclusion.ps1_ `::` Reads Windows Defender exclusion paths from the registry. Tells you exactly where you can drop and execute tools without triggering AV.

- _HistoryAndSecretsSweep.ps1_ `::` Sweeps all users' PowerShell history, SSH keys, unattend.xml, web configs, .env files, cloud credentials, and script content for embedded secrets.

- _KerberosPS.ps1_ `::` Pure PS Kerberos attack tool. Runs Kerberoasting, AS-REP Roasting, and Timeroasting in one shot. No Rubeus, no modules. Drops all hashes directly in Hashcat format with mode labels.

- _NonDefaultHunt.ps1_ `::` Enumerates third-party software via registry Uninstall keys and known portable paths. Pulls real versions from MSI manifests or PE VersionInfo `::` no path-name guessing.

- _PowerObfuscator.ps1_ `::` XOR+Base64 encrypts a target `.ps1` or `.exe` into a loader script with randomized variable names and junk code. .NET assemblies load fully in-memory via reflection.

- _PowerSmooth.ps1_ `::` Smooths PS execution by handling common runtime blockers. Run before other scripts when execution policy or environment restrictions interfere.

- _PsNmap.ps1_ `::` Pure PowerShell TCP port scanner. No binaries, no dependencies. Use when nmap is unavailable after landing on a Windows pivot.

- _RegistryCredsHunt.ps1_ `::` Hunts the registry for stored credentials: AutoLogon plaintext, WinSCP sessions (decrypted), PuTTY proxy passwords, VNC passwords (DES-decrypted), SNMP community strings, TeamViewer, OpenVPN, and mRemoteNG pointers.

- _Small-TaskProcess.ps1_ `::` Lightweight task and process utility for quick enumeration or manipulation of running processes and scheduled tasks without full tooling.

- _SmallStringsHunt.ps1_ `::` LDAP-first credential and string hunter. Queries Users, Computers, Groups, OUs, GPOs, Printers, and SMB shares for non-standard field values. Flags CredLike strings. Catches HTB Support-style `info` field passwords.

- _SwissArmy-Enum.ps1_ `::` General-purpose enumeration script covering system info, network config, users, groups, and common misconfigs in one pass.

---

## Python (Extra) Tools

python_to_power.py `::` Syntactic PS obfuscator that runs from Kali against any `.ps1` file. Strips comments, renames all variables and functions, splits flagged AV/AMSI strings, randomizes cmdlet casing, and inserts backticks. Output is `<name>_pychanged.ps1`.

```bash
python3 python_to_power.py NonDefaultHunt.ps1
python3 python_to_power.py SharpHound.ps1
```
