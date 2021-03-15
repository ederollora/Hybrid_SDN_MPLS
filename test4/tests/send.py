#!/usr/bin/env python
import sys, os , socket, random, struct, time
import argparse

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP, Raw
from scapy.fields import *

SRC = 0
DST = 1
DSCP = 2

BOS = 0
LABEL1 = 1
LABEL2 = 2

SWITCH_ID = 0
TIMESTAMP = 1

parser = argparse.ArgumentParser(description='Process some integers.')

parser.add_argument('-e', '--ethernet', type=str, help='Ethernet src/dst addresses')
parser.add_argument('-m', '--mpls', type=str, help='Enable MPLS header and add parameters')
parser.add_argument('-i', '--ip', type=str, help='Add IPv4 parameters')
parser.add_argument('-t', '--tcp', type=int, action='store', help='Enable TCP header and add parameters')
parser.add_argument('-u', '--udp', type=int, action='store', help='Enable UDP header and add parameters')
parser.add_argument('-l', '--intshim', const=True, action='store_const', help='Enable INT Shim header')
parser.add_argument('-n', '--intmeta', const=True, action='store_const', help='Enable INT Metadata header')
parser.add_argument('-s', '--imstack', type=str, help='Enable INT metadata stack using Switch ID and Timestamp')

parser.add_argument('-p', '--packets', type=int, action='store', help='Number of packets to send')
parser.add_argument('-b', '--bytes', type=int, action='store', help='Bytes for the payload')
parser.add_argument('-r', '--randbytes', const=True, action='store_const',  help='Add random bytes to the payload')
parser.add_argument('-f', '--filename', type=str, help='Path for the filename')
parser.add_argument('-c', '--interface', type=str, help='Name of the interface to send the packet to')


args = parser.parse_args()

class MPLS(Packet):
    name = "MPLS"
    fields_desc = [
        BitField("label", 1000, 20),
        BitField("exp", 0, 3),
        BitField("bos", 1, 1),
        ByteField("ttl", 0)
    ]

class INT_shim(Packet):
    oName = "INT Shim Header"

    fields_desc = [
        BitField('type', 1, 4),
        BitField('npt', 0, 2),
        BitField('res1', 0, 1),
        BitField('res2', 0, 1),
        ByteField('len', 0),
        ShortField('npt_field', 0)
    ]

class INT_meta(Packet):
    name = "INT Meta Header"

    fields_desc = [
        BitField('ver', 2, 4),
        BitField('d', 0, 1),
        BitField('e', 0, 1),
        BitField('m', 0, 1),
        BitField('rsvd1', 0, 12),
        BitField('hop_metadata_len', 2, 5),
        ByteField('remaining_hop_cnt', 0),
        BitField('instruction_mask_0003', 3, 4),
        BitField('instruction_mask_0407', 0, 4),
        BitField('instruction_mask_0811', 0, 4),
        BitField('instruction_mask_1215', 0, 4),
        ShortField('domain_sp_id', 0),
        ShortField('ds_inst', 0),
        ShortField('ds_flags', 0)
    ]

class INT_rep_grp(Packet):
    oName = "INT Report Group Header"

    fields_desc = [
        BitField('ver', 0, 4),
        BitField('f', 0, 6),
        BitField('i', 0, 22),
        BitField('rsvd', 0, 4)
    ]

class INT_rep_ind(Packet):
    oName = "INT Report Individual Header"

    fields_desc = [
        BitField('rep_type', 0, 4),
        BitField('in_type', 0, 4),
        ByteField('rep_len', 0),
        ByteField('md_len', 0),
        BitField('d', 0, 1),
        BitField('q', 0, 1),
        BitField('f', 0, 1),
        BitField('i', 0, 1),
        BitField('rsvd', 0, 4)
    ]

class INT_switch_id(Packet):
    name = "Switch ID"

    fields_desc = [
        IntField('switch_id', 0),
    ]

class INT_ingress_tstamp(Packet):
    name = "Ingress Timestamp"

    fields_desc = [
        IntField('ingress_global_timestamp', 0),
    ]


bind_layers(Ether, MPLS, type=0x8847)
bind_layers(MPLS,MPLS, bos=0)
bind_layers(MPLS, IP, bos=1)
bind_layers(INT_shim, INT_meta)

#bind_layers(UDP,INT_shim)
#bind_layers(TCP,INT_shim)


def main():

    if args.ethernet:
        ethernetParams = [p for p in args.ethernet.split(',')]

    if args.mpls:
        mplsParams = [int(p) for p in args.mpls.split(',')]

    if args.ip:
        ipParams = [p for p in args.ip.split(',')]

    if args.imstack:
        imstackParams = [p for p in args.imstack.split(',')]

    #outF = open(fileName, "a")

    print ("Sending packet interface %s" % (args.interface))

    for i in range(args.packets):
        pkt = Ether(src=ethernetParams[SRC], dst=ethernetParams[DST])

        if args.mpls:
            pkt = pkt / MPLS(label=mplsParams[LABEL1], bos=mplsParams[BOS])

        pkt = pkt / IP(src=ipParams[SRC], dst=ipParams[DST], tos=int(ipParams[DSCP], 0) << 2)

        if args.udp:
            pkt = pkt / UDP(sport=i+1, dport=args.udp)
        if args.tcp:
            pkt = pkt / TCP(sport=i+1, dport=args.tcp)
        if args.intshim:
            pkt = pkt / INT_shim(len=5)
            if args.intmeta:
                pkt = pkt / INT_meta()
                if args.imstack:
                    pkt = pkt / \
                          INT_switch_id(switch_id=int(imstackParams[SWITCH_ID])) / \
                          INT_ingress_tstamp(ingress_global_timestamp=int(imstackParams[TIMESTAMP]))

        if args.bytes:
            if args.randbytes:
                pkt = pkt / Raw(load=bytearray(os.urandom(args.bytes)))
            else:
                pkt = pkt / Raw(load= bytearray([0] * args.bytes) )

        #pkt.show()
        #t = time.time_ns()
        sendp(pkt, iface=args.interface, verbose=False)
        print("Sent packet: "+str(i+1))
        #outF.write(str(i+1)+","+str(t))
        #outF.write("\n")
        #time.sleep(0.1)


if __name__ == '__main__':
    main()
