# Linux Priviledges Escalation

## Gather Basic Informaiton

	whoami - what user are we running as
	id - what group does our user belong to
	hostname - what is the server named. can we gather any info from the naming convention
	ifconfig of ip a - what subnet did we land in, does the host have additional NICs in other subnets
	sudo -l - can our user run anything with sudo (as another user as root) without needing a password? This can sometimes be the easiest win and we can do something like sudo su and drop right into a root shell.
		if we can run a binary with sudo check which can be exploit in https://gtfobins.github.io/

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
	cat /etch/hosts
	getnet group <group_name> - check which members belong to an exinsting group
	lastlog - check the last logins in the system
	w - check the current login users

## Enumerate the home directory and history files

Check if the users are stoing significant information and configurations

	cat ./bash_history - Get the commands that have been executed by the user
	history - Get the commands that have been executed by the user (same as cat ./bash_history?)
	find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null - find history files that may have been created by services or scripts
	ls -la /etc/cron.daily/ - check the schedule jobs
	find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n" - find proc files that can give more information about the system

## Get all Hidden Files, Directories and temp files

	find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null
	find / -type d -name ".*" -ls 2>/dev/null
	ls -l /tmp /var/tmp /dev/shm

## Services

Check which services are in the system. They may be vulnurable to some exploit

	apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list - check packages installed
	sudo -V - check sudo version, old versions may have exploits
	for i in $(curl -s https://gtfobins.github.io/ | html2text | cut -d" " -f1 | sed '/^[[:space:]]*$/d');do if grep -q "$i" installed_pkgs.list;then echo "Check GTFO for: $i";fi;done - check which binaries in the system maybe exploited
	find / -type f \( -name *.conf -o -name *.config \) -exec ls -l {} \; 2>/dev/null - check config files for password, etc
	find / -type f -name "*.sh" 2>/dev/null | grep -v "src\|snap\|share" - scripts may have wrong priveledges, and may have other valuable information
	ps aux | grep root - check which services are beeing run by root

## Credential Hunting

When enumerating a system, it is important to note down any credentials. These may be found in configuration files (.conf, .config, .xml, etc.), shell scripts, a user's bash history file, backup (.bak) files, within database files or even in text files.

The /var directory typically contains the web root for whatever web server is running on the host. The web root may contain database credentials or other types of credentials that can be leveraged to further access.
Look for dabases runnings and grep the stored files (possibly also doing a strings command), to try to find the hashed passwords

grep -ri 'password'
grep -ri 'admin'

Check .ssh keys, and ssh known_hosts

	ls ~/.ssh

## Check priveledges

Check files that have setuid for root

	find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null

Check for files for the setgroupid

	find / -user root -perm -6000 -exec ls -ldb {} \; 2>/dev/null

## Run linPEAS script

	https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
	
	./linpeas.sh

## Relevante Information

	https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
	https://gtfobins.github.io/