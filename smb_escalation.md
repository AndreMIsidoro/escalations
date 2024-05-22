### 1st - Try Guest and Anonymous Authentication

	smbclient -N -L <hostname>
	smbclient \\\\<hostname>\\<sharename>>

### Use msfconsole to scan the smb version

In msfconsole

	use auxiliary/scanner/smb/smb_version
	set RHOSTS <target_ip>
	run

## Enumeration using netexec

enum4linux -a <target_ip>
nmap -v -p 445,139 <or_other_smb_ports> --script=smb* <target_ip>

https://www.netexec.wiki/smb-protocol/enumeration


## Use netexec to find valid usernames and passwords

	netexec smb heist.htb -u usernames.txt -p passwords.txt

use the --rid-brute option to possibly reveal other user names

	netexec smb heist.htb -u usernames.txt -p passwords.txt --rid-brute

## More Information

https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb#smb