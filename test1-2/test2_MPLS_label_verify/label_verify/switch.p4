#define ETHERTYPE_MPLS 0x8847
#define ETHERTYPE_IPV4 0x0800
#define IPPROTO_TCP 6
#define IP_PROTOCOLS_UDP 17
#define LDP_PORT 646
#define V00_NUM 768
#define ETHERTYPE_ARP  0x0806
#define ETHERTYPE_RARP 0x8035
#define ARP_PROTOTYPES_ARP_RARP_IPV4 0x0800

/*
 * Header declarations
 */

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type mpls_t {
    fields {
        label : 20;
        tc : 3;
        bos : 1;
        ttl : 8;
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        dscp: 6;
        ecn: 2;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr : 32;
    }
} // 20 bytes

header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 4;
        flags : 8;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}

header_type udp_t {
    fields {
        srcPort  : 16;
        dstPort  : 16;
        length_  : 16;
        checksum : 16;
    }
} // 8 bytes

/* INT shim header for TCP/UDP*/
header_type int_shim_t {
    fields {
        _type : 4;
        npt : 2;
        rsvd : 2;
        len : 8;
        npt_field : 16; // npt=0 -> , npt=1 -> orignal UDP port, npt=2 ->IP proto
    }
} // 4 bytes

/* INT-MD Metadata header v2.1*/
header_type int_meta_t {
    fields{
        ver : 4;
        d : 1;
        e : 1;
        m : 1;
        rsvd1 : 12;
        hop_metadata_len : 5;
        remaining_hop_cnt : 8;
        instruction_mask_0003 : 4; // check instructions from bit 0 to bit 3
        instruction_mask_0407 : 4; // check instructions from bit 4 to bit 7
        instruction_mask_0811 : 4; // check instructions from bit 8 to bit 11
        instruction_mask_1215 : 4; // check instructions from bit 12 to bit 15
        domain_sp_id : 16;
        ds_inst : 16;
        ds_flags : 16;
    }
} // 12 bytes

header_type int_label_verify_t {
    fields {
        id: 5;
        label: 20;
        port: 5;
        in_out: 1;
        bos: 1;
    }
}

header_type my_meta_t {
    fields {
        cur_id: 16;
    }
}

metadata my_meta_t my_meta;


parser start {
    return parse_ethernet;
}

header ethernet_t ethernet;

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_MPLS : parse_mpls;
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

header mpls_t mpls;

parser parse_mpls {
    extract(mpls);
    return parse_ipv4;
}

header ipv4_t ipv4;

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.protocol) {
        IPPROTO_TCP : parse_tcp;
        IP_PROTOCOLS_UDP : parse_udp;
        default: ingress;
    }
}

header tcp_t tcp;

parser parse_tcp {
    extract(tcp);
    return select(ipv4.dscp) {
        0x17 : parse_int_shim;
        default: ingress;
    }
}

header udp_t udp;

parser parse_udp {
    extract(udp);
	return ingress;
}

header int_shim_t int_shim;
header int_meta_t int_meta;

#define LABEL_DEPTH 4
header int_label_verify_t int_label_verify[LABEL_DEPTH];

parser parse_int_shim {
    extract(int_shim);
    return parse_int_meta;
}

parser parse_int_meta {
    extract(int_meta);
    return select(int_shim.rsvd) {
        0x1: parse_label_verify;
        default: ingress;
    }
}

parser parse_label_verify {
    extract(int_label_verify[next]);
    return select(latest.bos) {
        0 : parse_label_verify;
        default: ingress;
    }
}

/*
 * Ingress
 */

/* * */
action add_int(){

    //Validate headers
    add_header(int_shim);
    add_header(int_meta);

    //INT Shim
    modify_field(int_shim._type, 1);
    modify_field(int_shim.npt, 0);
    modify_field(int_shim.rsvd, 0);
    modify_field(int_shim.len, 3);
    modify_field(int_shim.npt_field, ipv4.dscp);

    // INT Meta
    modify_field(int_meta.ver, 2);
    modify_field(int_meta.d, 0);
    modify_field(int_meta.e, 0);
    modify_field(int_meta.m, 0);
    modify_field(int_meta.rsvd1, 0);
    modify_field(int_meta.hop_metadata_len, 0);
    modify_field(int_meta.remaining_hop_cnt, 2);
    modify_field(int_meta.instruction_mask_0003, 3);
    modify_field(int_meta.instruction_mask_0407, 0);
    modify_field(int_meta.instruction_mask_0811, 0);
    modify_field(int_meta.instruction_mask_1215, 0);
    modify_field(int_meta.domain_sp_id, 10);
    modify_field(int_meta.ds_inst, 2);
    modify_field(int_meta.ds_flags, 3);

    modify_field(ipv4.dscp, 0x17);
    modify_field(int_shim.rsvd, 0x1);
}

table tb_int {
    reads {
        standard_metadata.ingress_port : exact;
        ipv4.dstAddr: exact;
    }
    actions {
		add_int;
    }
}


action add_in_label1(my_id){
    add_header(int_label_verify[1]);
    modify_field(int_label_verify[1].id, my_id);
    modify_field(int_label_verify[1].label, mpls.label);
    modify_field(int_label_verify[1].port,0);
    modify_field(int_label_verify[1].in_out, 0);
    modify_field(int_label_verify[1].bos, 1);

    subtract(int_label_verify[1].port, standard_metadata.ingress_port, 0x300);

    modify_field(int_label_verify[0].bos, 0);
    add_to_field(int_meta.rsvd1, 1);
}

table tb_in_mpls {
    reads {
        standard_metadata.ingress_port : exact;
        ipv4.dstAddr: exact;
    }
    actions {
		add_in_label1;
    }
}

action add_out_label_1(my_id){
    add_header(int_label_verify[0]);
    modify_field(int_label_verify[0].id, my_id);
    modify_field(int_label_verify[0].label, mpls.label);
    modify_field(int_label_verify[0].port, 0);
    modify_field(int_label_verify[0].in_out, 1);
    modify_field(int_label_verify[0].bos, 1);

    subtract(int_label_verify[0].port, standard_metadata.egress_port, 0x300);

    add_to_field(int_meta.rsvd1, 1);
}

action add_out_label_2(my_id){
    add_header(int_label_verify[2]);
    modify_field(int_label_verify[2].id, my_id);
    modify_field(int_label_verify[2].label, mpls.label);
    modify_field(int_label_verify[2].port, 0);
    modify_field(int_label_verify[2].in_out, 1);
    modify_field(int_label_verify[2].bos, 1);

    subtract(int_label_verify[2].port, standard_metadata.egress_port, 0x300);

    modify_field(int_label_verify[1].bos, 0);
    add_to_field(int_meta.rsvd1, 1);
}

action add_out_label_3(my_id){
    add_header(int_label_verify[3]);
    modify_field(int_label_verify[3].id, my_id);
    modify_field(int_label_verify[3].label, mpls.label);
    modify_field(int_label_verify[3].port, 0);
    modify_field(int_label_verify[3].in_out, 1);
    modify_field(int_label_verify[3].bos, 1);

    subtract(int_label_verify[3].port, standard_metadata.egress_port, 0x300);

    modify_field(int_label_verify[2].bos, 0);
    add_to_field(int_meta.rsvd1, 1);
}

table tb_out_mpls {
    reads {
        standard_metadata.ingress_port : exact;
        ipv4.dstAddr: exact;
    }
    actions {
		add_out_label_1;
        add_out_label_2;
        add_out_label_3;
    }
}


/* * */

action mpls_fwd(label, egress_spec, dst_mac){
    modify_field(ethernet.dstAddr, dst_mac);
    modify_field(mpls.label, label);
    modify_field(standard_metadata.egress_spec, egress_spec);
}

table tb_mpls_fwd {
    reads {
        mpls.label: exact;
    }
    actions {
		mpls_fwd;
    }
}


/* * */

action add_mpls(){
    //Validate header
    add_header(mpls);

    //MPLS
    modify_field(mpls.label, 0);
    modify_field(mpls.tc, 0);
    modify_field(mpls.bos, 1);
    modify_field(mpls.ttl, 64);

    //Change Ethertype, mandatory
    modify_field(ethernet.etherType, 0x8847);
}

table tb_insert_mpls {
    reads {
        standard_metadata.ingress_port : exact;
        ipv4.dstAddr: exact;
    }
    actions {
		add_mpls;
    }

}


action cp_fwd(out_pt){
    modify_field(standard_metadata.egress_spec, out_pt);
}

table tb_cp_fwd {
    reads {
        standard_metadata.ingress_port : exact;
    }
    actions {
		cp_fwd;
    }
}

control ingress {

    apply(tb_insert_mpls);
    apply(tb_int);

    if(valid(int_shim)){
        apply(tb_in_mpls);
    }

    if(valid(mpls)){
        apply(tb_mpls_fwd);
    }else{
        apply(tb_cp_fwd);
    }
}


/*
 * Egress
 */


control egress {

    if(valid(int_shim)){
        apply(tb_out_mpls);
    }

}
