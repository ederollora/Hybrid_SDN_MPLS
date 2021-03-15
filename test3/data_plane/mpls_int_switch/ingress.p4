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

    Hash<bit<16>>(HashAlgorithm_t.IDENTITY) copy;
    Hash<bit<7>>(HashAlgorithm_t.IDENTITY) copy2;


    action int_set_header_0() { // 32 bits
        hdr.int_switch_id.setValid();
        hdr.int_switch_id.switch_id = meta.switch_id;
    }

    action int_set_header_1() { // 48 bits
        hdr.int_timestamp_gb.setValid();
        hdr.int_timestamp_gb.tstamp = ig_prsr_md.global_tstamp;
    }

    action int_set_header_0003_i3() {
        int_set_header_0();
        int_set_header_1();
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

        hdr.int_shim._type = 2;
        hdr.int_shim.npt = 0;
        hdr.int_shim.res1 = 0;
        hdr.int_shim.res2 = 0;
        //hdr.int_shim.len = 3;
        //hdr.int_shim.npt_field = (bit<16>)hdr.ipv4.dscp;
        //hdr.int_shim.npt_field = copy.get(hdr.ipv4.dscp);
        hdr.int_shim.npt_field = 0;
        // npt=0 ->, npt=1 -> orignal UDP port, npt=2 ->IP proto
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
    }

    action add_int_headers() {
        add_int_shim();
        add_int_meta();
        //hdr.ipv4.totalLen = hdr.ipv4.totalLen + 12;
        //hdr.udp._length = hdr.udp._length + 12;
    }

    /*table add_int_t {
        key = {
            hdr.mpls.label_id : exact;
        }
        actions = {
            add_int_headers;
            NoAction;
        }
        default_action = NoAction;
        size           = 10;
    }*/

    action remove_mpls_header() {
        hdr.mpls.setInvalid();
        hdr.ethernet.etherType = ETHERTYPE_IPV4;
    }

    action add_mpls_header(mpls_label_t label) {
        hdr.mpls.setValid();
        hdr.mpls.label_id = label;
        hdr.mpls.exp = 0;
        hdr.mpls.bos = 1;
        hdr.mpls.ttl = 64;

        hdr.ethernet.etherType = ETHERTYPE_MPLS;
        add_int_headers();
    }

    table mpls_add_t {
        key = {
            meta.switch_id   : exact;
            hdr.ipv4.srcAddr : exact;
        }
        actions = {
            add_mpls_header;
            add_int_headers();
            NoAction;
        }
        default_action = NoAction;
        size           = 10;
    }

    table mpls_rm_t {
        key = {
            meta.switch_id   : exact;
            hdr.ipv4.dstAddr : exact;
        }
        actions = {
            remove_mpls_header;
            NoAction;
        }
        default_action = NoAction;
        size           = 10;
    }

    action send_to(egressSpec_t port) {
        ig_tm_md.ucast_egress_port = port;
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
        size           = 10;
    }

    table ipv4_fwd_t {
        key = {
            hdr.ipv4.dstAddr : exact;
        }
        actions = {
            send_to;
            NoAction;
        }
        default_action = NoAction;
        size           = 10;
    }

    action get_switch_id(switch_id_t s_id){
        meta.switch_id = s_id;
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


        if (hdr.ipv4.isValid()) {
            process_switch_id.apply();

            if(!hdr.mpls.isValid()){
                mpls_add_t.apply();
            }else{
                mpls_rm_t.apply();
            }


            if(hdr.mpls.isValid()){
                //If MPLS still valid then fwd based on it
                mpls_fwd_t.apply();
            }else{
                //Else we are likely stripping MPLS and fwd based on IP
                ipv4_fwd_t.apply();
            }

            /*if(!hdr.int_shim.isValid() &&
                    !hdr.int_meta.isValid()){
                //Should I add INT headers?
                add_int_t.apply();
            }*/

            if(hdr.int_shim.isValid() && hdr.int_meta.isValid()){
                add_telemetry_t.apply();
            }
        }

    }

}
