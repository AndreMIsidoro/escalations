### 1st - Try Guest and Anonymous Authentication

	smbclient -N -L <hostname>
	smbclient \\\\<hostname>\\<sharename>>

### Use msfconsole to scan the smb version

In msfconsole

	use auxiliary/scanner/smb/smb_version
	set RHOSTS <target_ip>
	run

## Use nmap

	nmap -v -p 445,139 <or_other_smb_ports> --script=smb* <target_ip>

## Enumeration using netexec

netexec smb <target_ip> -u '' -p '' --shares
netexec smb <target_ip> -u '' -p '' --pass-pol


https://www.netexec.wiki/smb-protocol/enumeration

## Enumeration using smbmap:

smbmap -H <target_ip> --no-banner

Show he contentes of a share

	smbmap -H <target_ip> --no-banner -r <sharename>



## Use netexec to find valid usernames and passwords

	netexec smb heist.htb -u usernames.txt -p passwords.txt

use the --rid-brute option to possibly reveal other user names

	netexec smb heist.htb -u usernames.txt -p passwords.txt --rid-brute

## Cookbook

Download multiple files

	smbget -R smb://fileserver/directory

Mount a smb share:

	Install the cifs utils if not installed already
	sudo apt install cifs

	Create the dir the mount will be on:
	sudo mkdir /mnt/<dir_for_share>

	Finally mount the share:

	sudo mount -t cifs //hostname/sharename /mnt/dir_for_share/
	sudo mount -t cifs //nest.htb/Users /mnt/users/

	With username and pass:

	sudo mount -t cifs //nest.htb/Secure$ /mnt/secure -o username=TempUser,password=welcome2019

## More Information

https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb#smb