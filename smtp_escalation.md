# smtp Escalation


## Basic Enumeration

Grab banner

	nc -vn <target_ip> <smtp_port>

	nmap -v -p <smtp_port> --script smtp-commands <target_ip>
	nmap -v -p <smtp_port> --script smtp-open-relay <target_ip>

## Enum users

	nmap -v -p <smtp_port> --script smtp-enum-users <target_ip>


## General Enum

	Metasploit: auxiliary/scanner/smtp/smtp_enum

	nmap -v -p <smtp_port> --script smtp* <target_ip>