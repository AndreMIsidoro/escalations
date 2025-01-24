# shadow credentials

## Overview

The Kerberos authentication protocol works with tickets in order to grant access. An ST (Service Ticket) can be obtained by presenting a TGT (Ticket Granting Ticket). That prior TGT can only be obtained by validating a first step named "pre-authentication" (except if that requirement is explicitly removed for some accounts, making them vulnerable to ASREProast). The pre-authentication can be validated symmetrically (with a DES, RC4, AES128 or AES256 key) or asymmetrically (with certificates). The asymmetrical way of pre-authenticating is called PKINIT.

Active Directory user and computer objects have an attribute called msDS-KeyCredentialLink where raw public keys can be set. When trying to pre-authenticate with PKINIT, the KDC will check that the authenticating user has knowledge of the matching private key, and a TGT will be sent if there is a match.

There are multiple scenarios where an attacker can have control over an account that has the ability to edit the msDS-KeyCredentialLink (a.k.a. "kcl") attribute of other objects (e.g. member of a special group, has powerful ACEs, etc.). This allows attackers to create a key pair, append to raw public key in the attribute, and obtain persistent and stealthy access to the target object (can be a user or a computer).

This attack allows an attacker to take over an AD user or computer account if the attacker can modify the target object's (user or computer account) attribute msDS-KeyCredentialLink and append it with alternate credentials in the form of certificates.

## Attck Requirements

- The attacker needs to be in a domain that supports PKINIT and containing at least one Domain Controller running Windows Server 2016 or above.
- The attacker needs be in a domain where the Domain Controller(s) has its own key pair (for the session key exchange) (e.g. happens when AD CS is enabled or when a certificate authority (CA) is in place).
- The attacker needs to have control over an account that can edit the target object's msDs-KeyCredentialLink attribute.

## Attack Result

If the attack is executed successfully, the attacker will obtain a TGT and the NT Hash for the victim acccount

## Attack Exectuion

### With Certipy

https://github.com/Andre92Marcos/tools/tree/master/certipy-ad

certipy-ad shadow auto -u <username>@<domain_name> -p '<password>' -dc-ip <domain_controller_ip> -ns <dns_server_ip> -target <domain_controller_name>.<domain_name> -account <username_victim>



## More Information

    https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab
    https://posts.specterops.io/certified-pre-owned-d95910965cd2
    https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/shadow-credentials