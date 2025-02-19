# rogue potato

## Overview
Rogue Potato is a Windows privilege escalation attack that allows an attacker with SeImpersonatePrivilege to escalate their privileges to NT AUTHORITY\SYSTEM. It was developed as an evolution of Juicy Potato, which was patched in Windows 10 1809 and Windows Server 2019.

## How it works

- Windows allows certain privileged users to impersonate tokens of higher-privileged accounts (e.g., SYSTEM).
- The SeImpersonatePrivilege allows a process to assume the identity of another user.
- Many service accounts (e.g., IIS, MSSQL) have this privilege by default.


### Why Juicy Potato No Longer Works

- Juicy Potato exploited DCOM activation to create a SYSTEM token.
- Microsoft patched DCOM in Windows 10 1809+, making Juicy Potato ineffective.

### The Rogue Potato Attack

- Abuses NTLM Authentication & RPC instead of DCOM.
- Creates a fake RPC server to trick the system into authenticating as SYSTEM.
- Uses an NTLM relay attack to request a SYSTEM token.
- Once impersonation is successful, the attacker can execute commands as SYSTEM.

If Juicy Potato fails due to patches (Windows 10 1809+, Server 2019) use Rogue Potato


## Requirements

- Low-privileged user access to the system (standard user account) with the priviledges SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege.

## Other Inforamtion

https://github.com/antonioCoco/RoguePotato
