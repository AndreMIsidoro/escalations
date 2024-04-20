### 1st - Try Guest and Anonymous Authentication

	smbclient -N -L <hostname>
	smbclient \\\\<hostname>\\<sharename>>

### Use msfconsole to scan the smb version

In msfconsole

	use auxiliary/scanner/smb/smb_version
	set RHOSTS <target_ip>
	run
