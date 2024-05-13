### 1st - Try Guest and Anonymous Authentication

	smbclient -N -L <hostname>
	smbclient \\\\<hostname>\\<sharename>>

### Use msfconsole to scan the smb version

In msfconsole

	use auxiliary/scanner/smb/smb_version
	set RHOSTS <target_ip>
	run

### Use netexec to find valid usernames and passwords

	netexec smb heist.htb -u usernames.txt -p passwords.txt

use the --rid-brute option to possibly reveal other user names

	netexec smb heist.htb -u usernames.txt -p passwords.txt --rid-brute
