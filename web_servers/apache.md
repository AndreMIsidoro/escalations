# apache http server

## Common files to get/look

### httpd.conf or apache2.conf

Purpose: The main configuration file for the Apache HTTP Server.

Location: Often found in /etc/httpd/conf/httpd.conf (on Red Hat-based systems) or /etc/apache2/apache2.conf (on Debian-based systems).

Key Directives:

    ServerRoot: Defines the directory containing server files.
    DocumentRoot: Specifies the directory from which the server serves files.
    Listen: Configures the ports Apache listens on.
    ServerAdmin: Email address of the server administrator.
    ErrorLog and CustomLog: Paths to log files.
    Directory, Location, and Files blocks: Define access control and other behaviors.

### sites-available and sites-enabled

Purpose: sites-available/: Contains configurations for individual websites or virtual hosts. sites-enabled/: Symlinks to active site configurations from sites-available/.

Location: /etc/apache2/sites-available/ and /etc/apache2/sites-enabled/


### conf.d/ or extra/

Purpose: Directory containing additional configuration files for modular setups.

Location:Red Hat-based systems: /etc/httpd/conf.d/ Debian-based systems: /etc/apache2/conf-enabled/ May also appear as /etc/httpd/extra/ or similar.

Notes: Often includes files like: ssl.conf: SSL/TLS configuration. php.conf: Configuration for PHP. Other module-specific configurations.

### .htaccess

Purpose: Directory-level configuration file to override global or virtual host settings.

Location: Found in specific directories within DocumentRoot or other paths as allowed by the AllowOverride directive.

Use Cases: URL rewriting. Access control.Custom error documents. Setting environmental variables.