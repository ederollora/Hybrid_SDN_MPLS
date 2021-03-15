#!/usr/bin/env python
import sys
import struct
import binascii
import socket
import uuid
import json
from datetime import datetime
import calendar

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField, ByteField
from scapy.layers.inet import IP, ICMP, UDP, TCP, Raw
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
#from int_lib.telemetryreport import TelemetryReport

class INT_switch_id(Packet):
    name = "Switch ID"

    fields_desc = [
        IntField('switch_id', 0),
    ]

class INT_tstamp(Packet):
    name = "Timestamp"

    fields_desc = [
        BitField('timestamp', 0, 48),
    ]

class INT_shim(Packet):
    oName = "INT Shim"

    fields_desc = [
        BitField('_type', 0, 4),
        BitField('npt', 0, 2),
        BitField('res1', 0, 1),
        BitField('res2', 0, 1),
        ByteField('len', 0),
        ShortField('npt_field', 0)
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
        ShortField('domain_sp_id', 0),
        ShortField('ds_inst', 0),
        ShortField('ds_flags', 0)
    ]

def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]

def int2ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))

def extract_0003_i0():
    return
def extract_0003_i1(b):
    return
def extract_0003_i2(b):
    return
def extract_0003_i3(b):
    data = {}
    s_id = INT_switch_id(b[0:4])
    #s_id.show()
    tstamp_h = INT_tstamp(b[4:10])
    #tstamp_h.show()
    data["switch_id"] = s_id.switch_id
    data["timestamp"] = tstamp_h.timestamp
    return data
def extract_0003_i4(b):
    return
def extract_0003_i5(b):
    return
def extract_0003_i6(b):
    return
def extract_0003_i7(b):
    return
def extract_0003_i8(b):
    return
def extract_0003_i9(b):
    return
def extract_0003_i10(b):
    return
def extract_0003_i11(b):
    return
def extract_0003_i12(b):
    return
def extract_0003_i13(b):
    return
def extract_0003_i14(b):
    return
def extract_0003_i15(b):
    return



def extract_ins_00_03(instruction, b):

    if(instruction == 0):
        return extract_0003_i0(b)
    elif(instruction == 1):
        return extract_0003_i1(b)
    elif(instruction == 2):
        return extract_0003_i2(b)
    elif(instruction == 3):
        return extract_0003_i3(b)
    elif(instruction == 4):
        return extract_0003_i4(b)
    elif(instruction == 5):
        return extract_0003_i5(b)
    elif(instruction == 6):
        return extract_0003_i6(b)
    elif(instruction == 7):
        return extract_0003_i7(b)
    elif(instruction == 8):
        return extract_0003_i8(b)
    elif(instruction == 9):
        return extract_0003_i9(b)
    elif(instruction == 10):
        return extract_0003_i10(b)
    elif(instruction == 11):
        return extract_0003_i11(b)
    elif(instruction == 12):
        return extract_0003_i12(b)
    elif(instruction == 13):
        return extract_0003_i13(b)
    elif(instruction == 14):
        return extract_0003_i14(b)
    elif(instruction == 15):
        return extract_0003_i15(b)

def extract_ins_04_07(instruction, b):
    return

def extract_metadata_stack(b, total_data_len, hop_m_len, instruction_mask_0003, instruction_mask_0407, info):

    numHops = 2

    hop_m_len = 10

    info["instruction_mask_0003"] = instruction_mask_0003
    info["instruction_mask_0407"] = instruction_mask_0407
    info["data"] = {}

    #print("##[ INT Metadata Stack ]##")

    i=0
    for hop in range(numHops,0,-1):
        offset = i*hop_m_len
        #print("##[ Data from hop "+str(hop)+" ]##")
        info["data"]["hop_"+str(hop)] = {}
        if(instruction_mask_0003 != 0):
            data_0003 = extract_ins_00_03(instruction_mask_0003, b[offset:offset+hop_m_len])
            info["data"]["hop_"+str(hop)] = data_0003

        if(instruction_mask_0407 != 0):
            data_0407 = extract_ins_04_07(instruction_mask_0407, b[offset:offset+hop_m_len])
            info["data"]["hop_"+str(hop)].update(data_0407)

        i+=1

    return info

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "h4-eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find h4-eth0 interface"
        exit(1)
    return iface

def handle_pkt(packet, flows, counters):

    info = { }
    print("Handling report...")

    info["rec_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

    pkt = bytes(packet)
    #print "## PACKET RECEIVED ##"

    ICMP_PROTO = 1
    TCP_PROTO = 6
    UDP_PROTO = 17

    ETHERNET_HEADER_LENGTH = 14
    IP_HEADER_LENGTH = 20
    ICMP_HEADER_LENGTH = 8
    UDP_HEADER_LENGTH = 8
    TCP_HEADER_LENGTH = 20

    INT_REPORT_HEADER_LENGTH = 16
    INT_SHIM_LENGTH = 4
    INT_SHIM_WORD_LENGTH = 1
    INT_META_LENGTH = 12
    INT_META_WORD_LENGTH = 2
    INT_METADATA_STACK_LENGTH = 20

    ETHERNET_OFFSET = 0 + ETHERNET_HEADER_LENGTH
    IP_HEADER_OFFSET = ETHERNET_OFFSET + IP_HEADER_LENGTH
    L4_HEADER_OFFSET = IP_HEADER_OFFSET + TCP_HEADER_LENGTH

    INT_SHIM_OFF = 0 + INT_SHIM_LENGTH
    INT_META_OFF = INT_SHIM_OFF + INT_META_LENGTH
    INT_METADATA_STACK_OFFSET = INT_META_OFF + INT_METADATA_STACK_LENGTH


    eth_h = Ether(pkt[0:ETHERNET_OFFSET])
    ip_h = IP(pkt[ETHERNET_OFFSET:IP_HEADER_OFFSET])
    tcp_h = TCP(pkt[L4_HEADER_OFFSET:L4_HEADER_OFFSET+TCP_HEADER_LENGTH])
    raw_payload = bytes(packet[Raw])
    int_shim_h = INT_shim(raw_payload[0:INT_SHIM_LENGTH])
    int_meta_h = INT_meta(raw_payload[INT_SHIM_OFF:INT_SHIM_OFF + INT_META_LENGTH])

    eth_h.show()
    ip_h.show()
    #tcp_h.show()
    #int_shim_h.show()
    #int_meta_h.show()

    src_ip = (ip_h.src).strip("'")

    if src_ip not in counters:
        counters[src_ip] = 1
    else:
        counters[src_ip] = counters[src_ip] + 1

    stack_payload = raw_payload[INT_META_OFF:INT_META_OFF+INT_METADATA_STACK_LENGTH]
    info = extract_metadata_stack(stack_payload,\
                           INT_METADATA_STACK_LENGTH,
                           int_meta_h.hop_metadata_len * 4,\
                           int_meta_h.instruction_mask_0003,\
                           int_meta_h.instruction_mask_0407,\
                           info)

    #print("Time hop 2: %d" % (int(info["data"]["hop_2"]["timestamp"])))
    #print("Time hop 1: %d" % (info["data"]["hop_1"]["timestamp"]))
    #print("End-to-end time: %f ms" % ( )

    eeTime = int(info["data"]["hop_2"]["timestamp"]) -\
                                   int(info["data"]["hop_1"]["timestamp"])

    outF = open("data_"+src_ip+".txt", "a")
    outF.write(str(counters[src_ip])+","+str(eeTime))
    outF.write("\n")
    outF.close()

    sys.stdout.flush()

def main():
    flows = {}
    counters = {}

    iface = 'ens1f3'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(
        filter="tcp and port 1234",
        iface = iface,
        prn = lambda x: handle_pkt(x, flows, counters))

if __name__ == '__main__':
    main()
