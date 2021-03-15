control Ingress(
                /* User */
                inout my_ingress_headers_t                       hdr,
                inout my_ingress_metadata_t                      meta,
                /* Intrinsic */
                in    ingress_intrinsic_metadata_t               ig_intr_md,
                in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    bool int_added = false;

    action int_set_header_0() { // 32 bits
        hdr.int_switch_id.setValid();
        hdr.int_switch_id.switch_id = (bit<32>)hdr.common_metadata.switch_id;
    }

    action int_set_header_1() { // 32 bits
        hdr.int_timestamp_ig.setValid();
        hdr.int_timestamp_ig.igs = hdr.common_metadata.ts1;
    }

    action int_set_header_0003_i3() {
        int_set_header_0();
        int_set_header_1();
        // 4 bytes for switch_id and 8 bytes for ingress ts

        hdr.int_shim.len = hdr.int_shim.len +
            METADATA_8_BYTE_AS_WORDS;

        hdr.ipv4.totalLen = hdr.ipv4.totalLen +
            METADATA_4_BYTES; //we add ing tstamp size later

        hdr.udp.len = hdr.udp.len +
            METADATA_4_BYTES;

        hdr.common_metadata.added_int_metadata =
            hdr.common_metadata.added_int_metadata +
            METADATA_8_BYTE_AS_WORDS;
    }

    table add_telemetry_t {
        key = {
            hdr.int_meta.instruction_mask_0003 : exact;
        }
        actions = {
            int_set_header_0003_i3;
            NoAction;
        }
        default_action = NoAction();
        size = 2;
        const entries = {
            3 : int_set_header_0003_i3();
        }
    }

    action add_int_shim(){
        hdr.int_shim.setValid();

        hdr.int_shim._type = 1;
        // npt=0 ->, npt=1 -> orignal UDP port, npt=2 ->IP proto
        hdr.int_shim.npt = 0;
        hdr.int_shim.res1 = 0;
        hdr.int_shim.res2 = 0;
        hdr.int_shim.len = 0;

        hdr.int_shim.npt_field[15:8] = 0;
        hdr.int_shim.npt_field[7:2] = hdr.ipv4.dscp;
        hdr.int_shim.npt_field[1:0] = 0;
        //hdr.int_shim.npt_field = 0;
        hdr.ipv4.dscp = DSCP_INT;
    }

    action add_int_meta(){
        hdr.int_meta.setValid();

        hdr.int_meta.ver = 2;
        hdr.int_meta.d = 0;
        hdr.int_meta.e = 0;
        hdr.int_meta.m = 0;
        hdr.int_meta.rsvd1 = 0;
        hdr.int_meta.hop_metadata_len = 8;
        hdr.int_meta.remaining_hop_cnt = 64;
        hdr.int_meta.instruction_mask_0003 = 3;
        hdr.int_meta.instruction_mask_0407 = 0;
        hdr.int_meta.instruction_mask_0811 = 0;
        hdr.int_meta.instruction_mask_1215 = 0;
        hdr.int_meta.domain_sp_id = 0;
        hdr.int_meta.ds_inst = 0;
        hdr.int_meta.ds_flags = 0;

        //Added 2 words for metadata length
        hdr.int_shim.len = INT_META_HEADER_LEN_WORDS;
    }

    action add_int_headers() {
        add_int_shim();
        add_int_meta();
        int_added = true;
    }

    action add_mpls_header(mpls_label_t label) {
        hdr.mpls.setValid();
        hdr.mpls.label_id = label;
        hdr.mpls.exp = 0;
        hdr.mpls.bos = 1;
        hdr.mpls.ttl = 64;

        hdr.ethernet.etherType = ETHERTYPE_MPLS;
    }

    action exchange_mpls_label(mpls_label_t label) {
        hdr.mpls.label_id = label;
    }

    action remove_mpls_header() {
        hdr.mpls.setInvalid();
        hdr.ethernet.etherType = ETHERTYPE_IPV4;
    }

    action send_to(egressSpec_t port) {
        ig_tm_md.ucast_egress_port = port;
        hdr.common_metadata.output_port = port;
    }

    table mpls_add_t {
        key = {
            hdr.common_metadata.switch_id   : exact;
            hdr.ipv4.srcAddr                : exact;
        }
        actions = {
            add_mpls_header;
            NoAction;
        }
        default_action = NoAction;
        size           = 10;
    }

    table mpls_rm_t {
        key = {
            hdr.common_metadata.switch_id   : exact;
            hdr.ipv4.dstAddr                : exact;
        }
        actions = {
            remove_mpls_header;
            NoAction;
        }
        default_action = NoAction;
        size           = 10;
    }

    table mpls_exc_t {
        key = {
            hdr.mpls.label_id : exact;
        }
        actions = {
            exchange_mpls_label;
            NoAction;
        }
        default_action = NoAction;
        size           = 100;
    }

    table mpls_fwd_t {
        key = {
            hdr.mpls.label_id : exact;
        }
        actions = {
            send_to;
            NoAction;
        }
        default_action = NoAction;
        size           = 100;
    }

    table mpls_telemetry_t {
        key = {
            hdr.mpls.label_id : exact;
        }
        actions = {
            add_int_headers;
            NoAction;
        }
        default_action = NoAction;
        size           = 10;
    }

    table ipv4_fwd_t {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = {
            send_to;
            NoAction;
        }
        default_action = NoAction;
        size           = 10;
    }

    action get_switch_id(switch_id_t s_id){
        hdr.common_metadata.switch_id = (bit<8>)s_id;
    }

    table process_switch_id {
        key = {
            ig_intr_md.ingress_port : exact;
        }
        actions = {
            get_switch_id;
            NoAction;
        }
        default_action = NoAction;
        size           = 64;
    }

    table ldp_tcp_t {
        key = {
              hdr.ipv4.dstAddr : exact;
        }
        actions = {
            send_to;
            NoAction();
        }
        default_action = NoAction();
        size           = 10;
    }

    table ldp_udp_t {
        key = {
              ig_intr_md.ingress_port : exact;
              hdr.udp.dstPort         : exact;
        }
        actions = {
            send_to;
            NoAction();
        }
        default_action = NoAction();
        size           = 10;
    }

    table arp_t {
        key = {
              ig_intr_md.ingress_port : exact;
              hdr.ethernet.etherType : exact;
        }
        actions = {
            send_to;
            NoAction;
        }
        default_action = NoAction();
        size           = 10;
    }


    apply{

        if(arp_t.apply().hit){
            return;
        }

        if(hdr.udp.isValid()){
            if(ldp_udp_t.apply().hit){
                return;
            }
        }

        if(hdr.tcp.isValid()){
            if(ldp_tcp_t.apply().hit){
                return;
            }
        }

        hdr.common_metadata.setValid();
        hdr.common_metadata._pad = 0;
        hdr.common_metadata.added_int_metadata = 0;
        hdr.common_metadata.ts1 = (bit<32>)ig_intr_md.ingress_mac_tstamp;

        if (hdr.ipv4.isValid()) {
            process_switch_id.apply();

            mpls_add_t.apply();

            if(hdr.mpls.isValid()){

                //Is it time to remove MPLS?
                if(!mpls_rm_t.apply().hit){
                    // Exchange label if label is still there
                    mpls_exc_t.apply();
                };

                //Shall we add telemetry to this packet?
                mpls_telemetry_t.apply();
            }


            if(hdr.mpls.isValid()){
                //If MPLS still valid then fwd based on it
                mpls_fwd_t.apply();
            }else{
                //Else we are likely stripping MPLS and fwd based on IP
                //or just fwd based on IP
                ipv4_fwd_t.apply();
            }


            if(hdr.int_shim.isValid() && hdr.int_meta.isValid()){

                if(int_added){
                    hdr.ipv4.totalLen = hdr.ipv4.totalLen +
                        INT_SHIM_HEADER_LEN_BYTES;
                    hdr.ipv4.totalLen = hdr.ipv4.totalLen +
                        INT_META_HEADER_LEN_BYTES;
                    hdr.udp.len = hdr.udp.len +
                        INT_SHIM_HEADER_LEN_BYTES;
                    hdr.udp.len = hdr.udp.len    +
                        INT_META_HEADER_LEN_BYTES;
                }

                add_telemetry_t.apply();
            }

        }

    }

}
