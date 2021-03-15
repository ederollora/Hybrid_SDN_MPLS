#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from scapy.fields import *

class INT_ingress_tstamp(Packet):
    name = "Ingress Timestamp"

    fields_desc = [
        IntField('ingress_global_timestamp', 0),
    ]


class INT_shim(Packet):
    oName = "Telemetry Report Header"

    fields_desc = [
        BitField('int_type', 0, 4),
        BitField('npt', 0, 2),
        BitField('rsvd', 0, 2),
        BitField('len', 0, 8),
        BitField('npt_field', 0, 16)
    ]

class INT_meta(Packet):
    name = "INT Metadata Header"

    fields_desc = [
        BitField('ver', 0, 4),
        BitField('d', 0, 1),
        BitField('e', 0, 1),
        BitField('m', 0, 1),
        BitField('rsvd1', 0, 12),
        BitField('hop_metadata_len', 0, 5),
        ByteField('remaining_hop_cnt', 0),
        BitField('instruction_mask_0003', 0, 4),
        BitField('instruction_mask_0407', 0, 4),
        BitField('instruction_mask_0811', 0, 4),
        BitField('instruction_mask_1215', 0, 4),
        BitField('domain_sp_id', 0, 16),
        BitField('ds_inst', 0, 16),
        BitField('ds_flags', 0, 16),
    ]


class MPLS(Packet):
    name = "MPLS"
    fields_desc = [BitField("label", 3, 20),
                   BitField("tc", 0, 3),
                   BitField("bos", 1, 1),
                   ByteField("ttl", 0)]

#bind_layers(Ether, MPLS, type=0x8847)
#bind_layers(MPLS, IP, bos=1)
#bind_layers(MPLS,MPLS, bos=0)
#bind_layers(MPLS, INT_shim, bos=1)
#bind_layers(INT_shim, INT_meta)
#bind_layers(INT_meta, INT_ingress_tstamp)
#bind_layers(INT_meta, IP)
#bind_layers(INT_ingress_tstamp, IP)


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

    #addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print "sending on interface %s" % (sys.argv[1])
    pkt = Ether(src='c2:b9:86:fe:32:51', dst='c2:01:07:18:00:00')
    #pkt = pkt / MPLS(label = 1000, tc=0, bos = 1, ttl = 254)
    #pkt = pkt / INT_shim(int_type = 1, len = 3 )
    #pkt = pkt / INT_meta(ver = 1, hop_metadata_len = 1)# /
    #pkt = pkt / INT_ingress_tstamp(ingress_global_timestamp =  19088743)
    #pkt = pkt / INT_ingress_tstamp(ingress_global_timestamp =  2)
    pkt = pkt / IP(src=sys.argv[2], dst=sys.argv[3])
    pkt = pkt / TCP(dport=1234, sport=random.randint(49152,65535))
    pkt.show2()
    sendp(pkt, iface=sys.argv[1], verbose=False)


if __name__ == '__main__':
    main()
