# Windows Escaltion

## Gather Network Information

	ipconfig /all
	arp -a
	route print

## Enumerate Protections

	Get-MpComputerStatus
	Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
	Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone 		Tests Applocker policy

## Basic System Information

	echo %USERNAME%		Print current user
	whoami /priv		Displays current user privileges
	whoami /groups		Displays current user groups
	net user		Print all users
	net localgroup		Print all groups
	net localgroup <groupname>		Prints information of group
	tasklist /svc		Gives a better idea of what applications are running on the system. Prints the name of executables and services running
		https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/tasklist

	set		Prints env variables including PATH
	systeminfo		Prints information of the system, including hotfixes applied
		https://www.catalog.update.microsoft.com/Search.aspx?q=hotfix
		If systeminfo doesn't display hotfixes, they may be queriable with WMI using the WMI-Command binary with QFE (Quick Fix Engineering) to display patches.

		wmic qfe 
		https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page
		https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-quickfixengineering

		We can do this with PowerShell as well using the Get-Hotfix cmdlet.

		Get-HotFix | ft -AutoSize

	wmic product get name		Get installed programs
		or using powershell
		Get-WmiObject -Class Win32_Product |  select Name, Version

	netstat -ano		Display active tcp and udp connections
	query user		Display active users
	net accounts		Prints password policy

## Check communication through processess using pipes

	pipelist.exe /accepteula		enumerate instances of named pipes
		https://docs.microsoft.com/en-us/sysinternals/downloads/pipelist
	Get-ChildItem \\.\pipe\		enumerate instances of named pipes with powershell
	accesschk.exe /accepteula \\.\Pipe\<name_of_pipe> -v		Enumerate permissions of pipe. We are looking for a pipe we have WRITE permissions for our user
		https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk
	accesschk.exe -w \pipe\* -v		Enumerates all pipes that have WRITE permission


## Try WinPeas

	https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS

## More info

	https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md