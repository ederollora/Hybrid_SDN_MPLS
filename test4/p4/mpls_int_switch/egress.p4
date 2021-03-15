control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    //bit<16> sl = 0;

    action add_telemetry_report_header() {
        hdr.int_grp_report.setValid();
        hdr.int_grp_report.ver     = 2; //Latest spec
        hdr.int_grp_report.hw_id  = HW_ID;
        hdr.int_grp_report.seqNo   = 0; //=0 OK for latency tests
        hdr.int_grp_report.node_id = (bit<32>)hdr.common_metadata.switch_id;

        hdr.int_ind_report.setValid();
        hdr.int_ind_report.rep_type = REP_TYPE_INNER_ONLY;
        hdr.int_ind_report.in_type  = INNER_TYPE_IPV4;
        hdr.int_ind_report.rep_len  = 0;
        hdr.int_ind_report.rep_len  = INT_INDIV_REP_LEN_WORDS;
        hdr.int_ind_report.rep_len  = hdr.int_ind_report.rep_len  +
            INT_INDIV_REP_LEN_WORDS +
            IPV4_HEADER_LEN_WORDS   +
            INT_SHIM_HEADER_LEN_WORDS +
            hdr.int_shim.len;

        // md_len = 0 because no optional data
        hdr.int_ind_report.md_len   = 0;
        hdr.int_ind_report.d        = PACKET_NOT_DROPPED_WL;
        hdr.int_ind_report.q        = NOT_RELATED_TO_A_CONGESTED_QUEUE;
        hdr.int_ind_report.f        = TRACKED_FLOW;
        hdr.int_ind_report.i        = NOT_AN_INTERMEDIATE_REPORT;
        hdr.int_ind_report.rsvd     = 0;

        hdr.ethernet.setInvalid();

    }


    action create_outer_report_headers(macAddr_t src_mac, macAddr_t mon_server_mac,
                             ip4Addr_t src_ip,  ip4Addr_t mon_server_ip,
                             udp_port_t mon_server_port)
    {
        //Report Ethernet Header
        hdr.report_ethernet.setValid();
        hdr.report_ethernet.dstAddr = mon_server_mac;
        hdr.report_ethernet.srcAddr = src_mac;
        hdr.report_ethernet.etherType = ETHERTYPE_IPV4;

        //Report IPV4 Header
        hdr.report_ipv4.setValid();
        hdr.report_ipv4.version = 4; // ipv4
        hdr.report_ipv4.ihl = 5;     //i.e. 20 bytes
        hdr.report_ipv4.dscp = 0;
        hdr.report_ipv4.ecn = 0;

        /* Dont Fragment bit should be set */
        hdr.report_ipv4.identification = 0;
        hdr.report_ipv4.flags = 0;
        hdr.report_ipv4.fragOffset = 0;
        hdr.report_ipv4.ttl = 0xFF;
        hdr.report_ipv4.protocol = IPPROTO_UDP;
        hdr.report_ipv4.srcAddr = src_ip;
        hdr.report_ipv4.dstAddr = mon_server_ip;
        hdr.report_ipv4.totalLen = 0;

        //Report UDP Header
        hdr.report_udp.setValid();
        hdr.report_udp.srcPort = 1;
        hdr.report_udp.dstPort = mon_server_port;
        hdr.report_udp.len = hdr.ipv4.totalLen;

        hdr.report_udp.len = hdr.report_udp.len +
            UDP_HEADER_LEN_BYTES;
        hdr.report_udp.len = hdr.report_udp.len +
            INT_REP_GROUP_HEADER_LEN_BYTES;
        hdr.report_udp.len =
            INT_REP_INDIV_HEADER_LEN_BYTES;

        hdr.report_ipv4.totalLen = IPV4_HEADER_LEN_BYTES;

        hdr.report_ipv4.totalLen = hdr.report_ipv4.totalLen +
            hdr.report_udp.len;

        add_telemetry_report_header();

    }


    action rmv_int() {
        hdr.ipv4.dscp = hdr.int_shim.npt_field[7:2];

        hdr.ipv4.totalLen = hdr.ipv4.totalLen - ((bit<16>)8 << 2);
        hdr.udp.len =  hdr.udp.len - ((bit<16>)8 << 2);

        //hdr.ipv4.totalLen = hdr.ipv4.totalLen - (bit<16>)hdr.int_shim.len<< 2;
        //hdr.udp.len = hdr.udp.len - (bit<16>)hdr.int_shim.len<< 2;

        hdr.int_shim.setInvalid();
        hdr.int_meta.setInvalid();
        hdr.int_metadata_stack1.setInvalid();
        hdr.int_metadata_stack2.setInvalid();
    }

    table int_sink_t {
        key = {
            hdr.common_metadata.output_port : exact;
        }
        actions = {
            rmv_int;
            NoAction;
        }
        default_action = NoAction;
        size           = 128;
    }

    table int_report_t {
        key = {
            hdr.common_metadata.output_port : exact;
        }
        actions = {
            create_outer_report_headers;
            NoAction;
        }
        default_action = NoAction;
        size           = 132;
    }

    action add_egs_timestamp(bit<8> offset){

        eg_oport_md.update_delay_on_tx = 1;

        hdr.ptp_metadata.setValid();
        hdr.ptp_metadata.udp_cksum_byte_offset = 0;
        hdr.ptp_metadata.cf_byte_offset = offset;
        // we directly add egress_ts,
        // we don't try to calculate -ingress_ts + egress_ts
        hdr.ptp_metadata.updated_cf = 0;
        //hdr.int_timestamp_eg.setValid();
        //hdr.int_timestamp_eg.egs = 0;

        hdr.ipv4.totalLen = hdr.ipv4.totalLen + EGRESS_TS_SIZE_BYTES;
        hdr.udp.len = hdr.udp.len + EGRESS_TS_SIZE_BYTES;
    }

    table timestamp_eg_t {
        key = {
        }
        actions = {
            add_egs_timestamp;
            NoAction;
        }
        //default_action = add_egs_timestamp(46);
        default_action = NoAction;
        size           = 1;
    }


    apply {

        if(hdr.int_shim.isValid() && hdr.int_meta.isValid()){

            if(int_sink_t.apply().hit){
                //hdr.udp.len = sl;
            }

        }

        if(int_report_t.apply().hit){

            hdr.int_ind_report.rep_len  = hdr.common_metadata.added_int_metadata +
                hdr.int_ind_report.rep_len;

            if(hdr.udp.isValid()){
                hdr.int_ind_report.rep_len =
                    hdr.int_ind_report.rep_len +
                    UDP_HEADER_LEN_WORDS;
            }

            if(hdr.tcp.isValid()){
                hdr.int_ind_report.rep_len =
                    hdr.int_ind_report.rep_len +
                    TCP_HEADER_LEN_WORDS;
            }

            hdr.report_ipv4.totalLen = hdr.report_ipv4.totalLen + EGRESS_TS_SIZE_BYTES;
            hdr.report_udp.len = hdr.report_udp.len + EGRESS_TS_SIZE_BYTES;
        }

        if(!hdr.int_shim.isValid()){
            hdr.int_timestamp_ig.setValid();
            hdr.int_timestamp_ig.igs = hdr.common_metadata.ts1;
        }

        timestamp_eg_t.apply();
        hdr.common_metadata.setInvalid();

        //Ingress timestamp
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + INGRESS_TS_SIZE_BYTES;
        hdr.udp.len = hdr.udp.len + INGRESS_TS_SIZE_BYTES;
    }
}
