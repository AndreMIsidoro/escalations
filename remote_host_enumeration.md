## Scan ports
	
	sudo nmap -p- --min-rate=1000 <target_ip> > nmap.output

## Run nmap scripts on open ports **

	sudo nmap -p <open_ports> -sC -sV -vv -oN nmap.out <target_ip>

	or we can do

	ports=$(nmap -p- --min-rate=1000 <target_ip> | grep ^[0-9] | cut -d '/'​ -f 1 | tr ​'\n'​ ​','​ | awk '{print substr($0,1,length($0)-1)})
	nmap -sC -sV -O -p​$ports​ <target_ip>

	then do a UDP port scanning as well:

	sudo nmap --min-rate=1000 -sU <target_ip>

## Nmap scan when pivoting in a network

Using ligolo:

	nmap -F -sV -oN nmap.out -vv -iL targets.txt

Remember that ligolo nmap scan doesnt work with sudo options. Redo the scan to confirm

Using proxychains:

	proxychains nmap -n -Pn -F -sV -sT -oA nmap_results -vvv -iL targets.txt -T4 --max-retries 1 --max-rtt-timeout 2s --ttl 50ms --open


## Check the ports meaning

	Use https://www.speedguide.net/port.php?port=5985 to check the ports default service

## If we get versions of the services search for them in google for exploits and metasploit

