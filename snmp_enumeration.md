# snmp - Simple Network Managemnt enumeration

## Basic

snmpwalk -c public -v1 -t 10 <target_ip>
snmpwalk -c public -v2c -t 10 <target_ip>

snmpwalk -v X -c public <target_ip> NET-SNMP-EXTEND-MIB::nsExtendOutputFull