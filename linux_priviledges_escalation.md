# Linux Priviledges Escalation

## Gather Basic Informaiton

	whoami - what user are we running as
	id - what group does our user belong to
	hostname - what is the server named. can we gather any info from the naming convention
	ifconfig of ip a - what subnet did we land in, does the host have additional NICs in other subnets
	sudo -l - can our user run anything with sudo (as another user as root) without needing a password? This can sometimes be the easiest win and we can do something like sudo su and drop right into a root shell.