# PrintSpoofer

## Overview

PrintSpoofer is a privilege escalation vulnerability that exploits a flaw in the Windows Print Spooler service. This vulnerability allows attackers to gain SYSTEM privileges by manipulating the Print Spooler service, which runs with high privileges on Windows systems.

How PrintSpoofer Works:

- Abuses Print Spooler: The Print Spooler service is responsible for managing print jobs on Windows. It runs with high privileges, typically as SYSTEM.
- Malicious Printer Driver: The attack works by tricking the Print Spooler service into loading a malicious DLL. By controlling a specially crafted printer driver or spoofing a printer, an attacker can force the Print Spooler to execute malicious code with SYSTEM privileges.
- DLL Injection: The Print Spooler service can be tricked into executing a malicious DLL, giving the attacker the ability to run arbitrary code with elevated privileges.

Exploit Method:

- The attacker places a malicious DLL in a location that the Print Spooler service will load.
- By leveraging printer spoofing techniques, the attacker forces the Print Spooler to load and execute the malicious DLL.
- Once the DLL is loaded, the attacker gains SYSTEM privileges, effectively achieving full control over the machine.


## Attack Execution

https://github.com/itm4n/PrintSpoofer