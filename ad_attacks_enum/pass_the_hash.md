# Pass The Hash

## Overview

A Pass-the-Hash (PtH) attack is a type of cyberattack that allows an attacker to authenticate to a system using a hashed version of a password, rather than requiring the plaintext password itself. This type of attack exploits the way authentication protocols work in environments like Windows that use NTLM (NT LAN Manager) or Kerberos authentication.

Attackers gain access to a system and extract password hashes stored in memory, registry, or files. This is often achieved by exploiting vulnerabilities or misconfigurations, or through the use of malware or social engineering.

Instead of attempting to crack or decrypt the hash, attackers directly inject or replay the hash to authenticate to other systems or services. Authentication protocols like NTLM accept the hash as proof of identity if it matches the expected value on the target system.

Once authenticated, attackers can move laterally across the network, impersonating users whose hashes they have stolen. If an attacker captures the hash of a privileged user (e.g., a domain administrator), they can gain access to highly sensitive systems and data.

### Why PtH Attacks Are Effective

Reuse of Hashes: Many organizations do not regularly refresh or secure hashed credentials, allowing attackers to use stolen hashes over extended periods.

Default Behaviors: Windows systems often store hashed passwords in memory for authentication purposes, creating opportunities for attackers to extract them.

Trust in Authentication Protocols: NTLM and other protocols assume that possession of the hash equates to proof of identity.


### Why is Kerberos less vulnerable to Pass the Hash Attacks

Kerberos uses tickets (e.g., Ticket-Granting Ticket, or TGT) for authentication. These tickets are time-limited and are issued by a trusted third-party, the Key Distribution Center (KDC).

A user's password hash is only used once during the initial authentication with the KDC to obtain the TGT, and it is not transmitted or reused during subsequent sessions.

In PtH attacks, an attacker exploits systems that reuse static password hashes (like in NTLM). Since Kerberos does not reuse password hashes but instead uses temporary tickets, stealing a hash does not provide reusable credentials.

Kerberos tickets are encrypted with keys derived from the user’s password hash and the KDC’s secret key. Communications between clients and servers in Kerberos are also encrypted, protecting the credentials and tickets from interception.

Even if attackers intercept a Kerberos ticket or its encrypted form, they would need the secret keys to decrypt or reuse it, making it far harder to exploit than plaintext or reusable hashes.

Kerberos provides mutual authentication, where both the client and server prove their identities to each other. This prevents attackers from using stolen credentials to impersonate legitimate services or users without being detected. NTLM lacks mutual authentication, making it easier for attackers to perform PtH attacks or other replay attacks by impersonating legitimate users or systems.

Kerberos tickets are valid only for a limited time (e.g., 10 hours by default), after which they expire. Even if an attacker steals a Kerberos ticket, its usefulness is time-bound. In contrast, NTLM hashes do not have an expiration period, allowing attackers to reuse them indefinitely until passwords are changed.

Kerberos does not require the user’s password hash to be stored or transmitted across the network during normal operation. After the initial authentication, the TGT is used instead. NTLM often stores hashed credentials in memory or on disk (e.g., in the Security Account Manager or LSASS memory), creating opportunities for PtH attacks.

| **Feature**                     | **Kerberos**                        | **NTLM**                               |
|----------------------------------|--------------------------------------|----------------------------------------|
| **Reusability of Credentials**   | Temporary tickets                   | Static password hashes                 |
| **Encryption**                   | Encrypted tickets                   | Weak/no encryption for hashes          |
| **Mutual Authentication**        | Yes                                 | No                                     |
| **Time-Bound Authentication**    | Tickets expire                      | Hashes do not expire                   |
| **Credential Storage**           | Minimal local storage               | Often stored locally and in memory     |

### Vulnerable Services

   - **SMB (Server Message Block)**: Commonly used for file sharing and network communication. If attackers capture NTLM hashes, they can authenticate against SMB shares.
   - **RDP (Remote Desktop Protocol)**: Attackers can authenticate via RDP if they have the correct NTLM hash.
   - **Kerberos (when NTLM fallback is used)**: While Kerberos is more secure, it can fallback to NTLM, which is vulnerable to PtH attacks.
   - **NetLogon**: Services like Active Directory authentication use NTLM, making them vulnerable to PtH if hashes are compromised.
