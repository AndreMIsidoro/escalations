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

## evolution

If we want to read mails over imaps and pop3 is faster to just use a client like evolution:

```
sudo apt install evolution
```