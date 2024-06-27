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

## If you find an empty file in the share we can look for some hidden data:

Connect with smbclient
Then do:

	allinfo <name_of_file_that is empty>

And check if there are other streams, for example:

	stream: [::$DATA], 0 bytes
	stream: [:Password:$DATA], 15 bytes

Here the default data stream has 0 bytes, but the Password stream has 15 bytes.
We can download this data stream by doing:

	get <nameofile>:Password

## When we find valid credentials we can try rid brute to find other usernames

	netexec smb $targetip -u $username -p $password --rid-brute


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