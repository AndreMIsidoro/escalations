# Active Directory/Windows Attacks

## Remote Code Execution

### PrintNightmare

Affected versions

- Windows Server 2008 / 2008 R2
- Windows Server 2012 / 2012 R2
- Windows Server 2016
- Windows Server 2019
- Windows Server 2022

- Windows 7 (Extended Security Updates required to patch)
- Windows 8.1
- Windows 10 (All versions before July 2021 updates)
- Windows 11 (Early versions, before patches applied)

Check if is vulnerable:

```shell
rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'
```

https://github.com/AndreMIsidoro/escalations/blob/master/ad_attacks_enum/print_nightmare.md

## Local Privilege Escalation

### Juicy Potato

Affected Versions

- Windows 7 (particularly versions with User Account Control (UAC) disabled or misconfigured services).
- Windows 8.1 / 10 / Server 2016/2019 with COM permissions that allow low-privilege users to elevate privileges.
- Windows Server 2008 R2 to Windows Server 2019 (often in environments where COM service permissions or unquoted paths are mishandled).

Check if is vulnerable:

```powershell
whoami /priv | Select-String -Pattern "SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege"
```

https://github.com/AndreMIsidoro/escalations/blob/master/ad_attacks_enum/juicy_potato.md

### PrintNightmare

Affected versions

- Windows Server 2008 / 2008 R2
- Windows Server 2012 / 2012 R2
- Windows Server 2016
- Windows Server 2019
- Windows Server 2022

- Windows 7 (Extended Security Updates required to patch)
- Windows 8.1
- Windows 10 (All versions before July 2021 updates)
- Windows 11 (Early versions, before patches applied)

Check if system is vulnerable:

```powershell
#if the kbs (knowledge base) are not found, the system might be vulnerable
wmic qfe list brief | findstr /I "5004945 5004946 5004237 5004238 5005033 5005031 5005030 5005088"
```
https://github.com/AndreMIsidoro/escalations/blob/master/ad_attacks_enum/print_nightmare.md


### PrintSpoofer

Check If system is vulnerable:

```powershell
# check if the print spooler service is running
Get-Service -Name Spooler
#check if the system has been patched
wmic qfe list brief | findstr "KB5004945 KB5004953 KB5005033"
```

### Rogue Potato

Affected Versions

- Windows 10 1809 and later
- Windows Server 2019 and late

Check if is vulnerable:

```powershell
whoami /priv | Select-String -Pattern "SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege"
```

