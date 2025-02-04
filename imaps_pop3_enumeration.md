# imaps - pop3 enumeration

## Simple enumeration

sudo nmap -p<ports> -sV -sC <target_ip>

## imaps

Use credentials

curl -k 'imaps//<target_ip> --user <username>:<password> -v

Over tls

```
openssl s_client -connect <target_ip>:imaps
```


## pop3

Over tls

```
openssl s_client -connect <target_ip>:pop3s
```