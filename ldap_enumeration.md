# ldap - Enumeration

## Use ldapdomaindump

https://github.com/Andre92Marcos/tools/tree/master/ldapDomainDump

## Use netexec

https://github.com/Andre92Marcos/tools/blob/master/netexec/README.md#ldap

## When we get access to a domain user

Use bloodhound

   bloodhound-python -d <domain_name> -c all -u <username> -p <password> -ns <target_ip> --zip

   If we dont have the password of the user, we can download the sharphound.exe and run it directly on the user

Use responder to get hash and try to crack it

Use the snaffler tool

## Enumerate users found to see if they pre authenticate to kerberos

   kerbrute userenum --dc <ip_to_domain_controller> -d <full_domain_name>