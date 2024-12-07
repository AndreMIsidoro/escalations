# ldap Security Enumeration

## Windows Defender

Check if windwos defender is active:

    Get-MpComputerStatus

    Here, we can see that the RealTimeProtectionEnabled parameter is set to True, which means Defender is enabled on the system.

## App Locker

Check App Locker Policy

    Get-AppLockerPolicy

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