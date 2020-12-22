** 1st) Scan ports**
	
	sudo nmap -p- -T4 -sV -O 10.10.10.209 > nmap.output

** 2nd) Curl Target **

	curl 10.10.10.209 -o curl.output
