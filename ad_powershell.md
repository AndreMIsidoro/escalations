# AD Enumeration with Powershell

## Usage

Get Service account properties:

```powershell
Get-ADServiceAccount -Identity "Haze-IT-Backup$" -Properties PrincipalsAllowedToRetrieveManagedPassword
```