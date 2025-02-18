# JuicyPotato

## Overview

JuicyPotato is a privilege escalation exploit that leverages a vulnerability in the Windows operating system. Specifically, it exploits the Windows COM (Component Object Model) system to escalate privileges from a low-privileged user to SYSTEM level privileges.

https://github.com/ohpe/juicy-potato

## How JuicyPotato Works

JuicyPotato exploits DLL hijacking or service abuse in Windows. It typically takes advantage of:

- Unquoted service paths
- Abusive or misconfigured COM interfaces
- Insecure permissions on Windows services

It uses these vulnerabilities to inject code into a process running with SYSTEM privileges.

## Requirements for JuicyPotato

- Windows 7 or later (commonly used in Windows Server systems).
- The target system must have certain misconfigured services or insecure COM object permissions that allow the exploitation.
- Low-privileged user access to the system (standard user account) with the priviledges SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege.

## Execution

https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/juicypotato.html#examples