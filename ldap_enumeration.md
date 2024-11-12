# ldap - Enumeration

## Sync time with kerberos

To figure out the difference in time with the kerberos server:

   sudo ntpdate 10.129.127.130

To simulate the difference in time when executing a command:

   faketime -f '+7h' <command>

## Use ldapdomaindump

https://github.com/Andre92Marcos/tools/tree/master/ldapDomainDump

## Use netexec

https://github.com/Andre92Marcos/tools/blob/master/netexec/README.md#ldap

## When we get access to a domain user

Use bloodhound

   https://github.com/Andre92Marcos/tools/tree/master/bloodhound



Use the snaffler tool

## Enumerate users found to see if they pre authenticate to kerberos

   kerbrute userenum --dc <ip_to_domain_controller> -d <full_domain_name>

## If we can make the target make a smb request back to us

   For example using sqlinjection, we can use responder to get hash and try to crack it
   https://github.com/Andre92Marcos/tools/tree/master/responder