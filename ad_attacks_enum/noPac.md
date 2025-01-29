# NoPac - SamAccountName Spoofing

## Overview

This attack is the combination of two vulnerabilities.

CVE-2021-42278 - Name impersonation
Computer accounts should have a trailing $ in their name (i.e. sAMAccountName attribute) but no validation process existed to make sure of it. Abused in combination with CVE-2021-42287, it allowed attackers to impersonate domain controller accounts.

CVE-2021-42287 - KDC bamboozling
When requesting a Service Ticket, presenting a TGT is required first. When the service ticket is asked for is not found by the KDC, the KDC automatically searches again with a trailing $. What happens is that if a TGT is obtained for bob, and the bob user gets removed, using that TGT to request a service ticket for another user to himself (S4U2self) will result in the KDC looking for bob$ in AD. If the domain controller account bob$ exists, then bob (the user) just obtained a service ticket for bob$ (the domain controller account) as any other user.


## Attack Requirements

The ability to edit a machine account's sAMAccountName and servicePrincipalName.

## Attack Results

Get a shell as domain admin or be able to dcsync.

## Attack Execution

1. Clear the controlled machine account servicePrincipalName attribute of any value that points to its name (e.g. host/machine.domain.local, RestrictedKrbHost/machine.domain.local)
2. Change the controlled machine account sAMAccountName to a Domain Controller's name without the trailing $ -> CVE-2021-42278
3. Request a TGT for the controlled machine account
4. Reset the controlled machine account sAMAccountName to its old value (or anything else different than the Domain Controller's name without the trailing $)
5. Request a service ticket with S4U2self by presenting the TGT obtained before -> CVE-2021-42287
6. Get access to the domain controller (i.e. DCSync)

### With nopac.py

We can use this tool to perform this attack. NoPac uses many tools in Impacket to communicate with, upload a payload, and issue commands from the attack host to the target DC.

    https://github.com/Ridter/noPac

We can use the scripts in the NoPac directory to check if the system is vulnerable using a scanner (scanner.py) then use the exploit (noPac.py) to gain a shell as NT AUTHORITY/SYSTEM. We can use the scanner with a standard domain user account to attempt to obtain a TGT from the target Domain Controller. If successful, this indicates the system is, in fact, vulnerable.

    sudo python3 scanner.py <domain_name>/<domain_username>:<domain_user_password> -dc-ip <domain_controller_ip> -use-ldap

There are many different ways to use NoPac to further our access. One way is to obtain a shell with SYSTEM level privileges. We can do this by running noPac.py with the syntax below to impersonate the built-in administrator account and drop into a semi-interactive shell session on the target Domain Controller. This could be "noisy" or may be blocked by AV or EDR.

    sudo python3 noPac.py <domain_name>/<domain_username>:<domain_user_password> -dc-ip <domain_controller_ip>  -dc-host <domain_controller_host_name> -shell --impersonate administrator -use-ldap

Using noPac to DCSync the Built-in Administrator Account

    sudo python3 noPac.py <domain_name>/<domain_username>:<domain_user_password> -dc-ip <domain_controller_ip>  -dc-host <domain_controller_host_name> --impersonate administrator -use-ldap -dump -just-dc-user <domain_name>/administrator


## More Information

https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing
