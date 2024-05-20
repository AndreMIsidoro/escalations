# Web Server Escalation

## Use Wappalyzer to get more information from the web server

## Use the zap scanner

Use the zap scanner to look for vulnerabilities

## If we have the web server version, search for exploits

	https://www.cvedetails.com/
	https://www.exploit-db.com/

## Scan for subdomains

	Using knockpy
	Using dnsrecon

### Use gobuster to brute force hidden pages

	https://github.com/Andre92Marcos/tools/tree/master/gobuster

	gobuster dir -u http://<target_ip> -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt -t 20
	gobuster dir -u http://<target_ip> -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -t 20
	gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirb/big.txt -t 20

	gobuster  dns -d <hostname> -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -t 20

### Check common files

Check

	robot.txt
	README.txt



### Try default login of the running service

	admin:admin
	guest:guest
	user:user
	root:root
	administrator:password

	Try to search the default credentions for the webserver or webhost being used

	we can also try to do some brute force with common user passoword combinations

### Check cookies to see if we can manipulate them


### Check the list of possible vulnerabilities for web servers

	https://github.com/Andre92Marcos/vulnerabilities/tree/master/webservers
	For any input field try some:
		SQLInjection
		some xss - cross site scritting - https://github.com/Andre92Marcos/vulnerabilities/tree/master/webservers/xss_cross_site_scripting
		some ssi - server side injection
