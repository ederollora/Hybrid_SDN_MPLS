/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */


//@controller_header("packet_in")
header packet_in_header_t {
    bit<9> ingress_port;
    bit<7> _padding;
}

//@controller_header("packet_out")
header packet_out_header_t {
    bit<9> egress_port;
    bit<7> _padding;
}

/* Standard ethernet header */
header ethernet_h {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}


header mpls_h {
    mpls_label_t label_id;
    bit<3>       exp;
    bit<1>       bos;
    bit<8>       ttl;
}// 4 bytes

header ipv4_h {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> _length;
    bit<16> checksum;
}

/* INT shim header for TCP/UDP */
header int_shim_h {
    bit<4>  _type;
    bit<2>  npt;
    bit<1>  res1;
    bit<1>  res2;
    bit<8>  len;
    bit<16>  npt_field; // npt=0 -> , npt=1 -> orignal UDP port, npt=2 ->IP proto
} // 4 bytes

/* INT-MD Metadata header v2.1*/
header int_meta_h {
    bit<4> ver;
    bit<1> d;
    bit<1> e;
    bit<1> m;
    bit<12> rsvd1;
    bit<5> hop_metadata_len;
    bit<8> remaining_hop_cnt;
    bit<4> instruction_mask_0003; // check instructions from bit 0 to bit 3
    bit<4> instruction_mask_0407; // check instructions from bit 4 to bit 7
    bit<4> instruction_mask_0811; // check instructions from bit 8 to bit 11
    bit<4> instruction_mask_1215; // check instructions from bit 12 to bit 15
    bit<16> domain_sp_id;
    bit<16> ds_inst;
    bit<16> ds_flags;
} // 12 bytes

header int_switch_id_h {
    bit<32> switch_id;
} // 4 bytes

/*header int_ingress_port_h {
    bit<16> pad;
    bit<16> ingress_port;
}*/

header int_timestamp_gb_h {
    bit<48> tstamp;
} // 6 bytes


struct my_ingress_headers_t {
    packet_out_header_t   packet_out;
    packet_in_header_t    packet_in;
    ethernet_h            ethernet;
    mpls_h                mpls;
    ipv4_h                ipv4;
    tcp_h                 tcp;
    udp_h                 udp;
    int_shim_h            int_shim;
    int_meta_h            int_meta;
    int_switch_id_h       int_switch_id;
    //int_ingress_port_h    int_ingress_port;
    int_timestamp_gb_h    int_timestamp_gb;
}
