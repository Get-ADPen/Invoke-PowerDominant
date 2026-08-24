## Manual Commands

```powershell
Get-ADDomainController
```

```powershell
Get-ADUser
```

```powershell
Get-ADUser -Filter *
```

```powershell
Get-ADUser -Filter * | Select SamAccountName
```

```powershell
Get-AdUser -Filter * | ?{ $_.Enabled -eq "true" }
```

```powershell
Get-ADUser -Identity USER -Properties *
```

```powershell
Get-AdUser -Filter * -Properties * | Select Name, logonCount
```

```powershell
Get-ADUser -Filter 'Description -like "*built*"' -properties description | select name, description
```

```powershell
Get-ADComputer
```

```powershell
Get-AdComputer -Filter *
Get-AdComputer -Filter * | select Name
```

```powershell
Get-AdComputer -Filter * -Properties * | select Name, LastLogonDate, lastLogon, IPv4Address
```

```powershell
Get-ADGroup
Get-ADGroup -Filter * | select name
```

```powershell
Get-ADGroup -Filter * -Properties *
```

```powershell
Get-ADGroupMember -Identity "DNSAdmins" -Recursive 
```

```powershell
Get-ADPrincipalGroupMembership -Identity <USER>
```

PS: Pls create a Pull-request or submit on `Bug` nor `Suggestion` tab for more update. TY!!