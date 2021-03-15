#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP, Raw
from scapy.fields import *


def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if sys.argv[1] in i:
            iface=i
            break;
    if not iface:
        print "Cannot find "+sys.argv[1]+" interface"
        exit(1)
    return iface

def main():

    if len(sys.argv)<3:
        print 'pass 2 arguments: <destination> "<message>"'
        exit(1)

    iface = get_if()

    print "sending on interface %s" % (sys.argv[1])
    pkt = Ether(src='c2:b9:86:fe:32:51', dst='c2:01:07:18:00:00')
    pkt = pkt / IP(src=sys.argv[2], dst=sys.argv[3])
    pkt = pkt / TCP(dport=1234, sport=random.randint(49152,65535))
    pkt = pkt / Raw(load=sys.argv[4])
    #pkt.show2()
    sendp(pkt, iface=sys.argv[1], verbose=False)


if __name__ == '__main__':
    main()
