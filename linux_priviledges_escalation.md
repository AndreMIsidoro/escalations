# Linux Priviledges Escalation

## Gather Basic Informaiton

	whoami - what user are we running as
	id - what group does our user belong to
	hostname - what is the server named. can we gather any info from the naming convention
	ifconfig of ip a - what subnet did we land in, does the host have additional NICs in other subnets
	sudo -l - can our user run anything with sudo (as another user as root) without needing a password? This can sometimes be the easiest win and we can do something like sudo su and drop right into a root shell.

## Gather More Basic Infomation

	cat /etc/os-release - operating system and version
	echo $PATH - check what commands can and are been runned
	env - check any env variable for sensitive information
	uname -a - Get kernel version. Maybe it is a vulnerable kernel
	lscpu - Get information about the host architecture and cpu
	/etc/shells - Get what shells exist on the server. The shell the user is using might be vulnurable
	lsblk - Get information on blocks and devices on the system. An unmounted drive my contain senstive information
	cat /etc/fstab - Get information on blocks and devices on the system. An unmounted drive my contain senstive information
	route - What other networks are available
	arp -a - Check what other hosts the target has been communication with

## Gather More Basic Information

	cat /etc/passwd - check existing users
	cat /etc/group - check existing groups
	getnet group <group_name> - check which members belong to an exinsting group

## Enumerate the home directory

Check if the users are stoing significant information and configurations

	cat ./bash_history - Get the commands that have been executed by the user
	Check .ssh keys

## Get all Hidden Files, Directories and temp files

	find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null
	find / -type d -name ".*" -ls 2>/dev/null
	ls -l /tmp /var/tmp /dev/shm


## Run linPEAS script

	https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
