# Web Server Escalation

### 1s) Use gobuster to brute force hidden pages

	https://github.com/Andre92Marcos/tools/tree/master/gobuster

	gobuster dir -u http://<target_ip> -w /usr/share/wordlists/SecLists/Discovery/Web-Conten/directory-list-2.3-small.txt

### 2nd) Try default login

	admin:admin
	guest:guest
	user:user
	root:root
	administrator:password

### 3rd) Try some SQL Injection

	https://github.com/Andre92Marcos/sql_db/tree/master/sqlinjection
