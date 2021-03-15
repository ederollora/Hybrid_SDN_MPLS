#!/usr/bin/env python
import sys, os, socket, random, struct, time
import binascii, uuid, json
from datetime import datetime
import calendar
import argparse

from scapy.all import sniff, sendp, send, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField, ByteField
from scapy.all import Ether, IP, UDP, TCP, Raw
from scapy.layers.inet6 import IPv6
from scapy.fields import *

SRC = 0
DST = 1
DSCP = 2

BOS = 0
LABEL1 = 1
LABEL2 = 2

SWITCH_ID = 0
TIMESTAMP = 1

ICMP_PROTO = 1
TCP_PROTO = 6
UDP_PROTO = 17



parser = argparse.ArgumentParser(description='Process some parameters')

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
parser.add_argument('-x', '--filter', type=str, help='Filter criteria')
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
        BitField('type', 0, 4),
        BitField('npt', 0, 2),
        BitField('res1', 0, 1),
        BitField('res2', 0, 1),
        ByteField('len', 0),
        ShortField('npt_field', 0)
    ]

class INT_meta(Packet):
    name = "INT Meta Header"

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
        IntField('ingress_mac_tstamp', 0),
    ]

class INT_egress_tstamp(Packet):
    name = "Egress Timestamp"

    fields_desc = [
        BitField('egress_mac_tstamp', 0, 48),
        ShortField('egress_mac_tstamp_decimal', 1)
    ]


bind_layers(Ether, MPLS, type=0x8847)
bind_layers(MPLS,MPLS, bos=0)
bind_layers(MPLS, IP, bos=1)
bind_layers(INT_shim, INT_meta)


def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if args.interface in i:
            iface=i
            break;
    if not iface:
        print("Cannot find  interface")
        exit(1)
    return iface

def handle_pkt(packet, flows, counters):

    info = { }

    info["rec_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

    pkt = bytes(packet)
    #print "## PACKET RECEIVED ##"

    eth_h = None
    mpls_h = None
    ip_h = None
    l4_h = None

    iip_h = None
    il4_h = None
    int_report_grp_h  = None
    int_report_ind_h  = None

    int_shim_h = None
    int_meta_h = None
    int_stack_h = []
    igTimeStamp = None
    egTimeStamp = None
    packetPayload = None

    ETHERNET_HEADER_LENGTH = 14
    MPLS_HEADER_LENGTH = 4
    IP_HEADER_LENGTH = 20
    ICMP_HEADER_LENGTH = 8
    UDP_HEADER_LENGTH = 8
    TCP_HEADER_LENGTH = 20
    INT_REPORT_GROUP_HEADER_LENGTH = 8
    INT_REPORT_INDIV_HEADER_LENGTH = 4
    INT_SHIM_HEADER_LENGTH = 4
    INT_META_HEADER_LENGTH = 12

    INT_INGRESS_TSTAMP_LENGTH = 4
    INT_EGRESS_TSTAMP_LENGTH = 6

    INT_REPORT_PORT = 17171


    ETHERNET_OFFSET = 0 + ETHERNET_HEADER_LENGTH
    eth_h = Ether(pkt[0:ETHERNET_OFFSET])
    #eth_h.show()

    MPLS_HEADER_OFFSET = 0

    if eth_h.type == 0x8847:
        MPLS_HEADER_OFFSET = ETHERNET_OFFSET + MPLS_HEADER_LENGTH
        mpls_h = MPLS(pkt[ETHERNET_OFFSET:MPLS_HEADER_OFFSET])
        #mpls_h.show()

    L2_HEADER_OFFSET = 0
    if mpls_h:
        L2_HEADER_OFFSET = MPLS_HEADER_OFFSET
    else:
        L2_HEADER_OFFSET = ETHERNET_OFFSET

    IP_HEADER_OFFSET = L2_HEADER_OFFSET + IP_HEADER_LENGTH
    ip_h = IP(pkt[L2_HEADER_OFFSET:IP_HEADER_OFFSET])
    #ip_h.show()

    L4_HEADER_OFFSET = 0
    if ip_h.proto == UDP_PROTO:
        L4_HEADER_OFFSET = IP_HEADER_OFFSET + UDP_HEADER_LENGTH
        l4_h = UDP(pkt[IP_HEADER_OFFSET:L4_HEADER_OFFSET])
    elif ip_h.proto == TCP_PROTO:
        L4_HEADER_OFFSET = IP_HEADER_OFFSET + TCP_HEADER_LENGTH
        l4_h = TCP(pkt[IP_HEADER_OFFSET:L4_HEADER_OFFSET])
    else:
        print("No 17 or 6 IP proto")
        return

    #l4_h.show()

    eTmStampOffset = 0

    BREAKPOINT_OFFSET = L4_HEADER_OFFSET
    if ip_h.proto == UDP_PROTO and l4_h.dport == INT_REPORT_PORT:
        INT_REPORT_GROUP_HEADER_OFFSET = L4_HEADER_OFFSET + INT_REPORT_GROUP_HEADER_LENGTH
        int_report_grp_h = INT_rep_grp(pkt[L4_HEADER_OFFSET:INT_REPORT_GROUP_HEADER_OFFSET])
        #int_report_grp_h.show()
        eTmStampOffset += 8

        INT_REPORT_INDIV_HEADER_OFFSET = INT_REPORT_GROUP_HEADER_OFFSET + INT_REPORT_INDIV_HEADER_LENGTH
        int_report_ind_h = INT_rep_ind(pkt[INT_REPORT_GROUP_HEADER_OFFSET:INT_REPORT_INDIV_HEADER_OFFSET])
        #int_report_ind_h.show()
        eTmStampOffset += 4

        if int_report_ind_h.in_type != 0:
            print("Error in_type, not equal to 0: %d " % int_report_ind_h.in_type)

        INNER_IP_HEADER_OFFSET = INT_REPORT_INDIV_HEADER_OFFSET + IP_HEADER_LENGTH
        iip_h = IP(pkt[INT_REPORT_INDIV_HEADER_OFFSET:INNER_IP_HEADER_OFFSET])
        #iip_h.show()
        eTmStampOffset += 20

        INNER_L4_HEADER_OFFSET = 0
        if iip_h.proto == UDP_PROTO:
            INNER_L4_HEADER_OFFSET = INNER_IP_HEADER_OFFSET + UDP_HEADER_LENGTH
            il4_h = UDP(pkt[INNER_IP_HEADER_OFFSET:INNER_L4_HEADER_OFFSET])
        elif iip_h.proto == TCP_PROTO:
            INNER_L4_HEADER_OFFSET = INNER_IP_HEADER_OFFSET + TCP_HEADER_LENGTH
            il4_h = TCP(pkt[INNER_IP_HEADER_OFFSET:INNER_L4_HEADER_OFFSET])
        else:
            print("No 17 or 6 IP proto")
            return

        #il4_h.show()

        BREAKPOINT_OFFSET = INNER_L4_HEADER_OFFSET

    else:
        iip_h = ip_h
        il4_h = l4_h

    TSTAMP_OFFSET = BREAKPOINT_OFFSET

    if iip_h.tos == 0x5c:
        INT_SHIM_HEADER_OFFSET = BREAKPOINT_OFFSET + INT_SHIM_HEADER_LENGTH
        int_shim_h = INT_shim(pkt[BREAKPOINT_OFFSET:INT_SHIM_HEADER_OFFSET])
        #int_shim_h.show()
        eTmStampOffset += 4

        if int_shim_h.len >= 3: #at least 12 bytes fro int_meta
            INT_META_HEADER_OFFSET = INT_SHIM_HEADER_OFFSET + INT_META_HEADER_LENGTH
            int_meta_h = INT_meta(pkt[INT_SHIM_HEADER_OFFSET:INT_META_HEADER_OFFSET])
            #int_meta_h.show()
            eTmStampOffset = eTmStampOffset + 12

            INT_METADATA_STACK_OFFSET = INT_META_HEADER_OFFSET + ((int_shim_h.len - 3) * 4)
            if int_shim_h.len > 3:
                data = pkt[INT_META_HEADER_OFFSET:INT_METADATA_STACK_OFFSET]
                offset = 0
                int_stack_h = []
                for i in range(0, int_shim_h.len - 3, 2):
                    s_id = INT_switch_id(data[offset:offset+4])
                    #s_id.show()
                    tstamp = INT_ingress_tstamp(data[offset+4:offset+8])
                    #tstamp.show()
                    offset += 8
                    eTmStampOffset += 8
                    int_stack_h.append((s_id, tstamp))

            TSTAMP_OFFSET = INT_METADATA_STACK_OFFSET

    if not int_shim_h:
        INT_INGRESS_TSTAMP_OFFSET = TSTAMP_OFFSET + INT_INGRESS_TSTAMP_LENGTH
        igTimeStamp = INT_ingress_tstamp(pkt[TSTAMP_OFFSET:INT_INGRESS_TSTAMP_OFFSET])
        TSTAMP_OFFSET = INT_INGRESS_TSTAMP_OFFSET
    else:
        igTimeStamp = int_stack_h[0][1]

    INT_EGRESS_TSTAMP_OFFSET = TSTAMP_OFFSET + INT_EGRESS_TSTAMP_LENGTH
    egTimeStamp = INT_egress_tstamp(pkt[TSTAMP_OFFSET:INT_EGRESS_TSTAMP_OFFSET])

    PAYLOAD_OFFSET = INT_EGRESS_TSTAMP_OFFSET

    egTimeStamp_32 = egTimeStamp.egress_mac_tstamp & 0xffffffff
    igTimeStamp_32 = igTimeStamp.ingress_mac_tstamp

    #print("Ingress MAC timestamp: %d" % igTimeStamp_32)
    #print("Egress MAC timestamp: %d" % egTimeStamp_32)

    #packetPayload = bytes(packet[PAYLOAD_OFFSET:])

    pipelineLatency =  egTimeStamp_32 - igTimeStamp_32

    #print("Pipeline timestamp is %d ns" % pipelineLatency)

    #src_ip = (ip_h.src).strip("'")

    print("Received packet: %d" % il4_h.sport)

    outF = open("results_"+args.filename+".txt", "a")
    outF.write(str(il4_h.sport)+","+str(pipelineLatency))
    outF.write("\n")
    outF.close()

    sys.stdout.flush()

def main():
    flows = {}
    counters = {}

    print("sniffing on %s" % args.interface)
    sys.stdout.flush()
    sniff(
        filter = args.filter,
        iface = args.interface,
        prn = lambda x: handle_pkt(x, flows, counters))

if __name__ == '__main__':
    main()
