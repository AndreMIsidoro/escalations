# dns Enumeration

## Enumeration

```shell
nslookup http://<target_ip>
dig soa <domain>
dig soa www.inlanefreight.com
dig ns <domain> @<target_dns_server_ip>
```

## Zone transfer 

```shell
dnsrecon -d <target_ip> -t axfr
dig axfr <domain_name> @<target_dns_server_ip>
```

## Subdomain bruteforcing

```shell
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```

## Zone subdomain bruteforcing

```shell
dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt internal.inlanefreight.htb
```