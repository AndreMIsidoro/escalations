# ldap Security Enumeration

## Windows Defender

Check if windwos defender is active:

    Get-MpComputerStatus

    Here, we can see that the RealTimeProtectionEnabled parameter is set to True, which means Defender is enabled on the system.

## App Locker


Check App Locker Policy

    Get-AppLockerPolicy
    Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
	Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System31\cmd.exe -User Everyone 		Tests Applocker policy

## Powershell Constrainer Language Mode

Check if powershell is contrained

    $ExecutionContext.SessionState.LanguageMode

## LAPS - Local Administrator Password Solution

Show groups that have can read LAPS password

    Find-LAPSDelegatedGroups

Check computers with LAPS rights:

    Find-AdmPwdExtendedRight

Get computers with LAPS enabled:

    Get-LAPSComputers