parser EgressParser(packet_in        packet,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        packet.extract(eg_intr_md);
        packet.extract(hdr.common_metadata);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_MPLS: parse_mpls;
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_mpls {
        packet.extract(hdr.mpls);
        transition select((packet.lookahead<bit<4>>())[3:0]) {
            4w0x4   : parse_ipv4; /* IPv4 only for now */
            default : accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        //meta.dscp_save = (bit<16>)hdr.ipv4.dscp;
        transition select(hdr.ipv4.protocol) {
            IPPROTO_UDP  : parse_udp;
            IPPROTO_TCP  : parse_tcp;
            default      : accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.ipv4.dscp) {
            DSCP_INT     : parse_int_shim;
            default      : accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.ipv4.dscp) {
            DSCP_INT     : parse_int_shim;
            default      : accept;
        }
    }

    state parse_int_shim {
       packet.extract(hdr.int_shim);
       transition parse_int_meta;
    }

    state parse_int_meta {
        packet.extract(hdr.int_meta);
        transition select(hdr.int_shim.len) {
            8w7    : parse_int_metadata_stack2;
            8w5    : parse_int_metadata_stack1;
            default: accept;
        }
    }

     state parse_int_metadata_stack2 {
         packet.extract(hdr.int_metadata_stack2);
         transition parse_int_metadata_stack1;
     }

     state parse_int_metadata_stack1 {
         packet.extract(hdr.int_metadata_stack1);
         transition accept;
     }

    /*state parse_int_metadata_stack { //P4apps, Joghwan
        // Parse INT metadata, not INT header and INT shim header (length in bits)
        packet.extract(hdr.int_metadata_stack,  ((bit<32>) (hdr.int_shim.len - 3)) << 5);
        transition accept;
    }*/
}
