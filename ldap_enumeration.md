# ldap - Enumeration

## When we get access to a domain user

   Use bloodhound
   Use responder to get hash and try to crack it

## Enumerate users found to see if they pre authenticate to kerberos

   kerbrute userenum --dc <ip_to_domain_controller> -d <full_domain_name>

## With username and password

   bloodhound-python -d <domain_name> -c all -u <username> -p <password> -ns <target_ip> --zip