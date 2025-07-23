# ntp enumeration

## Basic Enumeration

```
ntpq -c readlist <IP_ADDRESS>
ntpq -c readvar <IP_ADDRESS>
ntpq -c peers <IP_ADDRESS>
ntpq -c associations <IP_ADDRESS>
ntpdc -c monlist <IP_ADDRESS>
ntpdc -c listpeers <IP_ADDRESS>
ntpdc -c sysinfo <IP_ADDRESS>
```

```shell
nmap -sU -sV --script "ntp* and (discovery or vuln) and not (dos or brute)" -p 123 <IP>
```

## Timeroasting

https://github.com/SecuraBV/Timeroast/tree/main
https://github.com/AndreMIsidoro/tools/tree/master/timeroast

## More Inforamtion

https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-ntp.html?highlight=ntp#123udp---pentesting-ntp