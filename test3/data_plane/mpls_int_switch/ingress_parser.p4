parser IngressParser(packet_in        packet,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
     state start {
        packet.extract(ig_intr_md);
        packet.advance(PORT_METADATA_SIZE);
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
          transition accept;
    }

}
