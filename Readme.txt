**************************

1. run_iptables.sh

The script for iptables configuration provided in the assignment specification
>> Please modify the VM Group ID for the variable "VMID" before running. <<

2, checksum.h

Header file to include for using "checksum.c"

3. checksum.c

Functions for calculating header checksums for a packet
i.e., "ip_checksum()" for IP headers, "tcp_checksum()" for TCP headers, and "udp_checksum()" for UDP headers

Usage: sudo ./nat <public ip> <internal ip> <subnet mask>
▪ Public IP: 10.3.1.2
▪ Internal IP: 10.0.2.[0-255]
▪ Subnet mask: 24
** Remember add sudo **

VM b - added route default gw 10.0.2.2
