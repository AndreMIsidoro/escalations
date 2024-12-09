# active directory attacks enumeration

## ACL

### Addself

    Addself abused with Add-DomainGroupMember

Shows security groups that a user can add themselves to.

### ForceChangePassword

    Abused with Set-DomainUserPassword

Gives us the right to reset a user's password without first knowing their password (should be used cautiously and typically best to consult our client before resetting passwords).

### GenericWrite

    Abused with Set-DomainObject

Gives us the right to write to any non-protected attribute on an object. If we have this access over a user, we could assign them an SPN and perform a Kerberoasting attack (which relies on the target account having a weak password set). Over a group means we could add ourselves or another security principal to a given group. Finally, if we have this access over a computer object, we could perform a resource-based constrained delegation attack which is outside the scope of this module.


### GenericAll

    Abused with Set-DomainUserPassword or Add-DomainGroupMember

This grants us full control over a target object. Again, depending on if this is granted over a user or group, we could modify group membership, force change a password, or perform a targeted Kerberoasting attack. If we have this access over a computer object and the Local Administrator Password Solution (LAPS) is in use in the environment, we can read the LAPS password and gain local admin access to the machine which may aid us in lateral movement or privilege escalation in the domain if we can obtain privileged controls or gain some sort of privileged access.


    WriteOwner abused with Set-DomainObjectOwner
    WriteDACL abused with Add-DomainObjectACL
    AllExtendedRights abused with Set-DomainUserPassword or Add-DomainGroupMember
    Add Members abused with Add-DomainGroupMember


## LLMNR/NBT-NS Poisoning

https://github.com/Andre92Marcos/vulnerabilities/blob/master/ldap/llmnr_ntbt-ns_poisoning.md

From Linux

    sudo responder -I <nerwork_interface>

## pass-the-ticket


## Shadow Credentials