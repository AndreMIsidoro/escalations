# joomla

## Overview

## Discovery

```shell
curl -s http://dev.inlanefreight.local/ | grep Joomla
```

We can fingerprint the Joomla version if the README.txt file is present.

```shell
curl -s http://dev.inlanefreight.local/README.txt | head -n 5
```

### Enumeration


```shell
sudo pip3 install droopescan
droopescan scan joomla --url http://dev.inlanefreight.local/
```

The default administrator account on Joomla installs is admin, but the password is set at install time, so the only way we can hope to get into the admin back-end is if the account is set with a very weak/common password and we can get in with some guesswork or light brute-forcing.

https://github.com/ajnik/joomla-bruteforce

```shell
sudo python3 joomla-brute.py -u http://dev.inlanefreight.local -w /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt -usr admin
```