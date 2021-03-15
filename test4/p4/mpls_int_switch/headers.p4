/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */


header common_metadata_t{
    bit<32>      ts1;
    egressSpec_t output_port;
    bit<7>       _pad;
    bit<8>       switch_id;
    bit<8>       insert_word_c;
    bit<8>       added_int_metadata;
}

/*header ptp_metadata_t {
    bit<8>  udp_cksum_byte_offset;
    //1) Eth+IPv4+UDP = 42 bytes
    //2) Eth+MPLS+IPv4+UDP = 48 bytes
    //3) Eth+MPLS+IPv4+UDP+I_S+I_M = 64 bytes
    //4) Eth+MPLS+IPv4+UDP+I_S+I_M = 64 bytes
    bit<8>  cf_byte_offset;
    bit<48> updated_cf;
}*/

/* Standard ethernet header */
header ethernet_h {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}//14 bytes

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
}//20 bytes

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
}//20 bytes

header udp_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> checksum;
}//8 bytes

/* INT shim header for TCP/UDP */
header int_shim_h {
    bit<4>  _type;
    bit<2>  npt;
    bit<1>  res1;
    bit<1>  res2;
    bit<8>  len;
    bit<16> npt_field; // npt=0 -> , npt=1 -> orignal UDP port, npt=2 ->IP proto
}//4 bytes

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
}// 12 bytes

header int_metadata_stack_h {
    bit<64> data;
}

header int_switch_id_h {
    bit<32> switch_id;
}// 4 bytes

/*header int_ingress_port_h {
    bit<16> pad;
    bit<16> ingress_port;
}*/

header int_timestamp_ig_h {
    bit<32> igs;
}// 6 bytes

header int_timestamp_eg_h {
    bit<64> egs;
}// 6 bytes

// Telemetry Report Group Header (2.0)
header int_report_group_h {
    bit<4> ver;
    bit<6> hw_id;
    bit<22> seqNo;
    bit<32> node_id;
}//8 bytes

// Individual Report Header (2.0)
header int_report_indiv_h {
    bit<4> rep_type;
    bit<4> in_type;
    // rep_len determines presence of multiple reports
    // corresponding to multiple data plane packets.
    // Shall be compared with UDP len.
    bit<8> rep_len;
    bit<8> md_len;
    bit<1> d;
    bit<1> q;
    bit<1> f;
    bit<1> i;
    bit<4> rsvd;
}//4 bytes

// Individual Report Main Contents for RepType 1 (INT)
// Not used
header int_indiv_main_h {
    bit<16> rep_md;
    bit<16> domain_sp_id;
    bit<16> ds_md;
    bit<16> dom_md_st;
}//8 bytes

// Individual Report Inner Contents for InType 1 (TLV)
//Not used
header int_indiv_inner_h {
    bit<4> tlv_type;
    bit<4> rsvd;
    bit<8> tlv_len;
    bit<16> tlv_temp;
}//4 bytes



struct my_ingress_headers_t {
    common_metadata_t     common_metadata;
    ptp_metadata_t        ptp_metadata;
    ethernet_h            ethernet;
    mpls_h                mpls;
    ipv4_h                ipv4;
    tcp_h                 tcp;
    udp_h                 udp;
    int_shim_h            int_shim;
    int_meta_h            int_meta;
    int_switch_id_h       int_switch_id;
    int_timestamp_ig_h    int_timestamp_ig;
    int_metadata_stack_h  int_metadata_stack2;
    int_metadata_stack_h  int_metadata_stack1;
}

struct my_egress_headers_t {
    common_metadata_t     common_metadata;
    ptp_metadata_t        ptp_metadata;
    ethernet_h            report_ethernet;
    ipv4_h                report_ipv4;
    udp_h                 report_udp;
    int_report_group_h    int_grp_report;
    int_report_indiv_h    int_ind_report;
    ethernet_h            ethernet; // 14
    mpls_h                mpls; // 4
    ipv4_h                ipv4; // 20
    tcp_h                 tcp;
    udp_h                 udp; // 8
    int_shim_h            int_shim; // 4
    int_meta_h            int_meta; // 12
    int_metadata_stack_h  int_metadata_stack2; // 4
    int_metadata_stack_h  int_metadata_stack1; // 4
    int_timestamp_ig_h    int_timestamp_ig; // 4
    //int_timestamp_eg_h    int_timestamp_eg; // 8
}
