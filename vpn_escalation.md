# vpn escalation

## Multiple vpns

When working with multiple vpns add an "mssfix 1400" (no quotes needed) to the vpn file. This helps because vpn wrapps a packet with data and if another vpn does it again it might be too much for the limit size of each packet