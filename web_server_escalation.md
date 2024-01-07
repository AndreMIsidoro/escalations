# Web Server Escalation

### Use Wappalyzer to get more information from the web server

## Use the zap scanner

Use the zap scanner to look for vulnerabilities

## If we have the web server version, search for exploits

	https://www.cvedetails.com/
	https://www.exploit-db.com/

### Use gobuster to brute force hidden pages

	https://github.com/Andre92Marcos/tools/tree/master/gobuster

	gobuster dir -u http://<target_ip> -w /usr/share/wordlists/SecLists/Discovery/Web-Conten/directory-list-2.3-small.txt
	gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirb/big.txt

	Use -x to search for specific pages like .html and pages for the specific programming language (like .php)

### Try default login of the running service

	admin:admin
	guest:guest
	user:user
	root:root
	administrator:password

	we can also try to do some brute force with common user passoword combinations

### Check cookies to see if we can manipulate them

### Try some SQL Injection

	https://github.com/Andre92Marcos/sql_db/tree/master/sqlinjection

### Check the list of possible vulnerabilities for web servers

	https://github.com/Andre92Marcos/vulnerabilities/tree/master/webservers

