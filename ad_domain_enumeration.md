# Active Directory - Domain Enumeration

### Using PowerView

Get Current Domain

```powershell
Get-Domain
Get-Domain -Domain <DomainName>
Get-DomainSID
```
Get Domain Policy

```powershell
Get-DomainPolicy

#Will show us the policy configurations of the Domain about system access or kerberos
Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess
Get-DomainPolicy | Select-Object -ExpandProperty KerberosPolicy
```

Get Domain Controllers

```powershell
Get-DomainController
Get-DomainController -Domain <DomainName>
```

Get Domain OUs

```powershell
Get-DomainOU -Properties Name | Sort-Object -Property Name
```

Get Domain Trusts

```powershell
Get-DomainTrust
Get-DomainTrust -Domain <DomainName>

#Enumerate all trusts for the current domain and then enumerates all trusts for each domain it finds
Get-DomainTrustMapping
```

Get Forest Trust

```powershell
Get-ForestDomain
Get-ForestDomain -Forest <ForestName>

#Map the Trust of the Forest
Get-ForestTrust
Get-ForestTrust -Forest <ForestName>
```

Enumerate Domain Users

```powershell
#Save all Domain Users to a file
Get-DomainUser | Out-File -FilePath .\DomainUsers.txt

#Will return specific properties of a specific user
Get-DomainUser -Identity [username] -Properties DisplayName, MemberOf | Format-List

Get-DomainUser -Identity [domain_username] -Domain [domain_name] | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol | Format-List

#Get users with SPN property set
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName

#Get users with password not required property set
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol

#Get users with dont req preauth property set
Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl

#Enumerate user logged on a machine
Get-NetLoggedon -ComputerName <ComputerName>

#Enumerate Session Information for a machine
Get-NetSession -ComputerName <ComputerName>

#Enumerate domain machines of the current/specified domain where specific users are logged into
Find-DomainUserLocation -Domain <DomainName> | Select-Object UserName, SessionFromName
```

User hunting

```powershell
#Finds all machines on the current domain where the current user has local admin access
Find-LocalAdminAccess -Verbose

#Find local admins on all machines of the domain
Find-DomainLocalGroupMember -Verbose

#Find computers were a Domain Admin OR a specified user has a session
Find-DomainUserLocation | Select-Object UserName, SessionFromName

#Confirming admin access
Test-AdminAccess
```

Enumerate Domain Computers

```powershell
Get-DomainComputer -Properties OperatingSystem, Name, DnsHostName | Sort-Object -Property DnsHostName

#Enumerate Live machines
Get-DomainComputer -Ping -Properties OperatingSystem, Name, DnsHostName | Sort-Object -Property DnsHostName
```

Enumerate Group Policies

```powershell
Get-DomainGPO -Properties DisplayName | Sort-Object -Property DisplayName

#Enumerate all GPOs to a specific computer
Get-DomainGPO -ComputerIdentity <ComputerName> -Properties DisplayName | Sort-Object -Property DisplayName

#Get users that are part of a Machine's local Admin group
Get-DomainGPOComputerLocalGroupMapping -ComputerName <ComputerName>
```

Enumerate Groups and Group Members

```powershell
#Save all Domain Groups to a file:
Get-DomainGroup | Out-File -FilePath .\DomainGroup.txt

#Return members of Specific Group (eg. Domain Admins & Enterprise Admins)
Get-DomainGroup -Identity '<GroupName>' | Select-Object -ExpandProperty Member
Get-DomainGroupMember -Identity '<GroupName>' | Select-Object MemberDistinguishedName

#Enumerate the local groups on the local (or remote) machine. Requires local admin rights on the remote machine
Get-NetLocalGroup | Select-Object GroupName

#Enumerates members of a specific local group on the local (or remote) machine. Also requires local admin rights on the remote machine
Get-NetLocalGroupMember -GroupName Administrators | Select-Object MemberName, IsGroup, IsDomain

#Return all GPOs in a domain that modify local group memberships through Restricted Groups or Group Policy Preferences
Get-DomainGPOLocalGroup | Select-Object GPODisplayName, GroupName

#Get users in groups that do not belong the domain
Get-DomainForeignGroupMember -Domain [domain_name]
```

Enumerate Shares

```powershell
#Enumerate Domain Shares
Find-DomainShare

#Enumerate Domain Shares the current user has access
Find-DomainShare -CheckShareAccess

#Enumerate "Interesting" Files on accessible shares
Find-InterestingDomainShareFile -Include *passwords*
```

Enumerate Acls

```powershell
# Returns the ACLs associated with the specified account
Get-DomaiObjectAcl -Identity <AccountName> -ResolveGUIDs

#Search for interesting ACEs
Find-InterestingDomainAcl -ResolveGUIDs| ConvertTo-Json


Get ACL permissions of an user
$sid = Convert-NameToSid <username>
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}

#Check the ACLs associated with a specified path (e.g smb share)
Get-PathAcl -Path "\\Path\Of\A\Share"
```

## Tips

### Restore deleted users

Confirm that the recycle bin feature is enabled:
```powershell
Get-ADOptionalFeature -Filter 'Name -like "*Recycle Bin*"'
```

Check if the account is indeed deleted:

```powershell
Get-ADObject -Filter * -IncludeDeletedObjects -SearchBase "CN=Deleted Objects,DC=voleur,DC=htb" -Properties *
```

Grap the deleted account distinguished name and restore it (usually contains 0ADEL):

```powershell
Restore-ADObject -Identity "CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb"
```

Confirm restoration:

```powershell
Get-ADUser Todd.Wolfe| Select DistinguishedName
```

## Other Information

https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet

