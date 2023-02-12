** 1st) Scan ports**
	
	sudo nmap -p- -T4 -A 10.10.10.209 > nmap.output
	nmap -p- --min-rate=1000 -sV <target_ip> > namp.output

** 2nd) Curl Target **

	curl 10.10.10.209 -o curl.output

** 3rd) Run nmap scripts on open ports **

	sudo nmap -p <open_ports> -sC <target_ip>
