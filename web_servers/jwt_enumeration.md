# jwt enumeration

## Attacks

### Algorithm Confusion Attacks

An algorithm confusion attack generally involves the following high-level steps:

- Obtain the server's public key
- Convert the public key to a suitable format
- Create a malicious JWT with a modified payload and the alg header set to HS256.
- Sign the token with HS256, using the public key as the secret.

https://portswigger.net/web-security/jwt/algorithm-confusion