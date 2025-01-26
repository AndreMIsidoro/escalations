# Web Server Escalation

## Use Wappalyzer to get more information from the web server

## If we have the web server version, search for exploits

	https://www.cvedetails.com/
	https://www.exploit-db.com/

## If the webserver is using https check the certificate

SSL/TLS certificates are another potentially valuable source of information if HTTPS is in use. Viewing the certificate reveals the details below, including the email address and company name. These could potentially be used to conduct a phishing attack if this is within the scope of an assessment.

## Scan for subdomains

	Using ffuzz
		ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -u http://<domain> -H "Host: FUZZ.<domain>"
		if there are many false positives we can filter them out by number of words
		ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -u http://<domain> -H "Host: FUZZ.<domain>" -fw <number_words_false_positives>

### Scan for dirs and pages

```
	ffuf -u http://<target_ip>/FUZZ -w /usr/share/wordlists/dirb/wordlists/common.txt
	ffuf -u http://<target_ip>/FUZZ -w <mywordlist> #https://github.com/AndreMIsidoro/tools/blob/master/wordlists/my_webserver_files.txt
	feroxbuster --url http://<target_ip>
	ffuf -u http://<target_ip>/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list.2.3-medium.txt
```

### Crawl using sqlmap

	sqlmap -u http://<target_ip> --crawl=1


### Check common files


	ffuf -u http://<target_ip>/FUZZ -w <my_wordlist>

	https://github.com/Andre92Marcos/tools/blob/master/wordlists/my_webserver_files.txt

### Check the Headers fo http response from the server


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
