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

Check if system in vulnerable:

```powershell
#if the kbs (knowledge base) are not found, the system might be vulnerable
wmic qfe list brief | findstr /I "5004945 5004946 5004237 5004238 5005033 5005031 5005030 5005088"
```
https://github.com/AndreMIsidoro/escalations/blob/master/ad_attacks_enum/print_nightmare.md

