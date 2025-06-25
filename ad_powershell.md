# AD Enumeration with Powershell

## Usage

Get Service account properties:

```powershell
Get-ADServiceAccount -Identity "Haze-IT-Backup$" -Properties PrincipalsAllowedToRetrieveManagedPassword
```

Set Service account propterty:

```powershell
Set-ADServiceAccount -Identity "Haze-IT-Backup$" -PrincipalsAllowedToRetrieveManagedPassword "mark.adams"
```