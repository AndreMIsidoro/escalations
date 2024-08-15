# Web Server Escalation

## Use Wappalyzer to get more information from the web server

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

Using gobuster:

	gobuster dir -u http://<target_ip> -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt -t 20
	gobuster dir -u http://<target_ip> -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -t 20
	gobuster dir -u http://<target_ip> -w /usr/share/wordlists/dirb/big.txt -t 20

Using ffuf:

	ffuf -u http://<target_ip>/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list.2.3-small.txt


### Check common files


	ffuf -u http://<target_ip>/FUZZ -w <my_wordlist>

	https://github.com/Andre92Marcos/tools/blob/master/wordlists/my_webserver_files.txt


### If we find a login form use the request to try some default passwords

	https://github.com/Andre92Marcos/tools/blob/master/wordlists/my_defaul_usernames.txt
	https://github.com/Andre92Marcos/tools/blob/master/wordlists/my_default_passwords.txt

	Try to search the default credentials for the framework

### Check cookies to see if we can manipulate them

### If there are pages with forms:

	Try sql map injection on the fiels:
	https://github.com/Andre92Marcos/tools/tree/master/sqlmap


### Check the list of possible vulnerabilities for web servers

	Read the vulns to keep getting better at them

	https://github.com/Andre92Marcos/vulnerabilities/tree/master/webservers

	Try some file inclusions:

		ffuf -w /usr/share/wordlists/file_inclusion_windows.txt -u http://mailing.htb/download.php?file=FUZZ

	For any input field try some:
		SQLInjection
		some xss - cross site scritting - https://github.com/Andre92Marcos/vulnerabilities/tree/master/webservers/xss_cross_site_scripting
		some ssi - server side injection
		some ssfr - https://github.com/Andre92Marcos/vulnerabilities/tree/master/webservers/ssrf
			ssfrmap

### If we can't find an exploit view the source code
