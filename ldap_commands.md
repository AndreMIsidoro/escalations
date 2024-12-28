# ldap - Commands

## Important commands

klist    View and manage Kerberos Tickets


## Living of the land Commands - Host

Print all users

    net user

Print all groups

    net localgroup

Print information of specific group

    net localgroup <groupname>

Print current shares

    net share

Get a list of computers

    net view



## Living of the land Commands - Domain

Retrieves information about the password and account policies of the domain

    net accounts /domain

Retrieves information about the account of the domain

    net user <account_domain_name> /domain

Retrieves information about the groups of the domain

    net groups /domain

Retrieves information about a specific group of the domain

    net groups <domain_group_name> /domain

Get list of computer on a domain

    net view /domain

## Living of the land - dsquery

The dsquery DLL exists on all modern Windows systems by default now and can be found at C:\Windows\System32\dsquery.dll

Get list of users

    dsquery user

Get users with property password not required set:

    dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))" -attr distinguishedName userAccountControl


Get all domain controllers ina a domain

dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)" -attr sAMAccountName

Get list of computers

    dsquery computer

View all objects in a OU

    dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"





## Native Active Directory Module

https://github.com/Andre92Marcos/tools/tree/master/activeDirectoryPowershellModule

Import-Module ActiveDirectory

Basic information about the domain

    Get-ADDomain

Get accounts with property ServicePrincipalName set

    Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

Get domain trust relationships

    Get-ADTrust -Filter *

Get domain group names

    Get-ADGroup -Filter * | select name

Get detailed information about a specific domain group

    Get-ADGroup -Identity "<domain_group_name>"

Get list of users that belong to a group

    Get-ADGroupMember -Identity "<domain_group_name>"


## Powerview

https://github.com/Andre92Marcos/tools/blob/master/powersploit/PowerView.md

import-module .\Powerview.ps1

Shows domain password policy

    Get-DomainPolicy

Get information about a domain user

    Get-DomainUser -Identity <domain_username> -Domain <domain_name> | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol

Get users with SPN property set

    Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName

Get users with password not required property set

    Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol

Get users with dont req preauth property set

    Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl

Get all groups of a domain

    Get-DomainGroup -Domain <domain_name>

Get a specific group of a domain

    Get-DomainGroup -Domain <domain_name> -Identity "<group_name>"

Get users that belong to a specific group

    Get-DomainGroupMember -Identity "<domain_group_name>" -Recurse

Get users in groups that do not belong the domain

    Get-DomainForeignGroupMember -Domain <domain_name>


Get the SID of a domain

    Get-DomainSID

Get domain trust relationships

    Get-DomainTrust
    Get-DomainTrustMapping

Test local admin access to remote machine

    Test-AdminAccess -ComputerName <computer/host_name>

Get ACL permissions of an user

    $sid = Convert-NameToSid <username>
    Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}

Change a user password

    $newpassword = ConvertTo-SecureString '<new_password>' -AsPlainText -Force
    Set-DomainUserPassword -Identity <username_of_user_we_want_to_change> -AccountPassword $newpassword -Verbose
