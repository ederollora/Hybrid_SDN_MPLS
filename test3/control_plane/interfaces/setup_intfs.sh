
#!/bin/bash

sudo ip address add 192.168.99.1 dev ens1f0
sudo ip addr add 192.168.99.1/24 broadcast 192.168.99.255 dev ens1f0
sudo arp -s 192.168.99.2 c2:01:07:18:00:00

sudo ip address add 192.168.98.1 dev ens1f1
sudo ip addr add 192.168.98.1/24 broadcast 192.168.98.255 dev ens1f1
sudo arp -s 192.168.98.2 c2:01:07:18:00:00

#route add -net 10.0.1.0/24 gw 10.0.1.1
#arp -s 10.0.1.1 00:00:00:00:11:11

#route add -net 10.0.2.0/24 gw 10.0.2.1
#arp -s 10.0.2.1 00:00:00:00:22:22
