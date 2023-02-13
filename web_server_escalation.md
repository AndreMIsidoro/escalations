# Web Server Escalation

### 1s) Use gobuster to brute force hidden pages

	https://github.com/Andre92Marcos/tools/tree/master/gobuster

	gobuster dir -u http://<target_ip> -w /usr/share/wordlists/SecLists/Discovery/Web-Conten/directory-list-2.3-small.txt
