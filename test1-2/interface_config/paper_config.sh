
#sudo ip link set dev vf0_2 address 00:15:4D:01:01:01
#sudo ip link set dev vf0_8 address 00:15:4D:02:01:01
#sudo ip link set dev vf0_11 address 00:15:4D:03:01:01
#sudo ip link set dev vf0_12 address 00:15:4D:02:02:02

sudo ifconfig vf0_2 192.168.99.1 netmask 255.255.255.0
sudo ifconfig vf0_5 192.168.100.1 netmask 255.255.255.0
sudo ifconfig vf0_6 192.168.101.1 netmask 255.255.255.0
sudo ifconfig vf0_11 192.168.102.1 netmask 255.255.255.0

sudo ip route add 192.168.200.1/32 dev vf0_2
sudo ip route add 192.168.200.2/32 dev vf0_5
sudo ip route add 192.168.201.1/32 dev vf0_6
sudo ip route add 192.168.201.2/32 dev vf0_11


sudo ethtool -K vf0_2 rx off tx off
sudo ethtool -K vf0_5 rx off tx off
sudo ethtool -K vf0_6 rx off tx off
sudo ethtool -K vf0_11 rx off tx off
