## Scan ports
	
	sudo nmap -p- -T4 -A 10.10.10.209 > nmap.output
	sudo nmap -p- --min-rate=1000 -sV -sS <target_ip> > nmap.output

## Run nmap scripts on open ports **

	sudo nmap -p <open_ports> -sC <target_ip>

## Check the ports meaning

	Use https://www.speedguide.net/port.php?port=5985 to check the ports default service

## Use the zap scanner

	Use the zap spider scanner and then the active spider scanner to look for vulnerabilities