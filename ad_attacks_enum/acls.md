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


### GenericAll

    Abused with Set-DomainUserPassword or Add-DomainGroupMember

This grants us full control over a target object. Again, depending on if this is granted over a user or group, we could modify group membership, force change a password, or perform a targeted Kerberoasting attack. If we have this access over a computer object and the Local Administrator Password Solution (LAPS) is in use in the environment, we can read the LAPS password and gain local admin access to the machine which may aid us in lateral movement or privilege escalation in the domain if we can obtain privileged controls or gain some sort of privileged access.

We can also add the dont_req_preauth setting so that the account is ASREProastable:

```
bloodyAD --host <dc_controller_name> -d "domain_name" --dc-ip <domain_controller_ip> -k add uac <username_of_target_account> -f DONT_REQ_PREAUTH
```

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

### WriteOwner

    Abuse with bloodyAD

    bloodyAD --host <host_ip> -d '<domain_name>' -u '<username>' -p '<password>' set owner <group_name> <name_of_new_owner>
    dacledit.py -action 'write' -rights 'FullControl' -principal '<username_of_new_owner>' -target '<username_being_owned>' '<domain_name>'/'<username_new_owner>':'<password_new_owner>' # to give full control

https://github.com/Andre92Marcos/tools/tree/master/bloodyAD
