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
	Using ffuzz
		ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -u http://<domain> -H "Host: FUZZ.<domain>"
		if there are many false positives we can filter them out by number of words
		ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -u http://<domain> -H "Host: FUZZ.<domain>" -fw <number_words_false_positives>

### Use gobuster to brute force hidden pages

	https://github.com/Andre92Marcos/tools/tree/master/gobuster

	gobuster dir -u http://<target_ip> -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt -t 20
	gobuster dir -u http://<target_ip> -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -t 20
	gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirb/big.txt -t 20

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

	Read the vulns to keep getting better at them

	https://github.com/Andre92Marcos/vulnerabilities/tree/master/webservers

	Try some file inclusions:

		ffuf -w /usr/share/wordlists/file_inclusion_windows.txt -u http://mailing.htb/download.php?file=FUZZ

	For any input field try some:
		SQLInjection
			sqlmap
		some xss - cross site scritting - https://github.com/Andre92Marcos/vulnerabilities/tree/master/webservers/xss_cross_site_scripting
		some ssi - server side injection
		some ssfr - https://github.com/Andre92Marcos/vulnerabilities/tree/master/webservers/ssrf
			ssfrmap

### If we can't find an exploit view the source code
