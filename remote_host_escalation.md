## Scan ports
	
	sudo nmap -p- --min-rate=1000 <target_ip> > nmap.output

## Run nmap scripts on open ports **

	sudo nmap -p <open_ports> -sC -sV <target_ip>

## Check the ports meaning

	Use https://www.speedguide.net/port.php?port=5985 to check the ports default service

## If we get versions of the services search for them in google for exploits

