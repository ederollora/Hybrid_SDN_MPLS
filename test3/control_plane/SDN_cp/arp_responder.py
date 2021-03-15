from __future__ import print_function
from scapy.all import Ether, ARP, IP, UDP, TCP
from scapy.all import *
import time

# Your network broadcast address
broadcastNet = "10.0.0.255"

macDict = { "10.0.0.100" : "00:00:00:00:FF:01"}

# Use MAC address of this machine as source. If not eth0, change this:
myMAC = get_if_hwaddr('tap0')


def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "tap0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find vf0_0 interface")
        exit(1)
    return iface


def handle_packet(packet):
    if packet[ARP].op == ARP.who_has:
        #print("Someone is asking about " + packet.pdst)
        #print(packet.summary())
        iface = get_if()


 
        if packet.pdst in macDict:
            print("Sending ARP response for " + packet.pdst)
            reply = ARP(op=ARP.is_at, hwsrc=macDict[packet.pdst], psrc=packet.pdst, hwdst=packet.hwsrc, pdst=packet.psrc)
            go = Ether(dst=packet.hwsrc, src=myMAC) / reply
            sendp(go,iface=iface)
    return

# Sniff for ARP packets. Run handle_packet() on each one
sniff(filter="arp",prn=handle_packet)
