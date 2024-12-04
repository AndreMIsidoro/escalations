# smb Enumeration

## Check Sessions

### Anonymous Session

Try to create an anonymous session and list the shares:

	smbclient -N -L <hostname>

If there are shares to access we can try to connect doing:

	smbclient \\\\<hostname>\\<sharename>>

We can print all files of a share by doing:

	smbclient \\\\<hostname>\\sharename -c 'recurse;ls'

### Null Session

	netexec smb <target-ip> -u '' -p ''

### Guest Session

	netexec smb <target-ip> -u 'randomusername' -p 'randompassword'
	netexec smb <target-ip> -u 'Guest' -p ''


If we found a session with netexec then do:

	--shares
	--pass-pol
	--users
	--groups

	-M spider_plus #creates a file tree of the shares
	-M spider_plus -o DOWNLOAD_FLAG=True # to dump all files

	To download a specific file we can use smbmap

## Test users

	netexec smb <target_ip> -u usernames.txt -p passwords.txt --continue-on-success

## When we have a valid username and password

Try to rid-brute force

	netexec smb heist.htb -u 'Guest' -p '' --rid-brute #Guest default password is blank

This valid user might be the default user 'Guest'

## Try local authentication

Adding --local-auth to any of the authentication commands with attempt to logon locally.

	nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --local-auth

## More netexec enum

	https://www.netexec.wiki/smb-protocol/enumeration

## Use msfconsole to scan the smb version

In msfconsole

	use auxiliary/scanner/smb/smb_version
	set RHOSTS <target_ip>
	run

## Use nmap

	nmap -v -p 445,139 <or_other_smb_ports> --script=smb* <target_ip>


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


## If we have an account with read/write permission

We can psexec into that account

	https://github.com/Andre92Marcos/tools/tree/master/psexec


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