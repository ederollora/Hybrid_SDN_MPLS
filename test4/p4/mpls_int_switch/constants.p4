const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<16> ETHERTYPE_VLAN = 0x8100;
const bit<16> ETHERTYPE_MPLS = 0x8847;
const bit<16> ETHERTYPE_IPV4 = 0x0800;

const bit<8>  IPPROTO_IPv4   = 0x04;
const bit<8>  IPPROTO_TCP   = 0x06;
const bit<8>  IPPROTO_UDP   = 0x11;

//Header lengths

// Length, in bytes
const bit<16> ETHERNET_HEADER_LEN_BYTES       = 14;
const bit<16> MPLS_HEADER_LEN_BYTES           = 4;
const bit<16> IPV4_HEADER_LEN_BYTES           = 20;
const bit<16> UDP_HEADER_LEN_BYTES            = 8;
const bit<16> TCP_HEADER_LEN_BYTES            = 20;
const bit<16> INT_SHIM_HEADER_LEN_BYTES       = 4;
const bit<16> INT_META_HEADER_LEN_BYTES       = 12;
const bit<16> INT_REP_GROUP_HEADER_LEN_BYTES  = 8;
const bit<16> INT_REP_INDIV_HEADER_LEN_BYTES  = 4;
const bit<16> METADATA_4_BYTES                = 4;
const bit<16> METADATA_8_BYTES                = 8;
const bit<16> WORD_TO_BYTES                   = 4;


const bit<6> DSCP_INT = 0x17; //DSCP

const bit<8> ETHERNET_HEADER_SIZE_BYTES = 14;
const bit<8> UDP_HEADER_SIZE_BYTES = 8;
const bit<8> TELEMETRY_REPORT_HEADER_LEN_BYTES = 16;


const bit<16> INGRESS_TS_SIZE_BYTES = 4; //in bytes
const bit<16> INGRESS_TS_SIZE_WORDS = 1; //in bytes
const bit<16> EGRESS_TS_SIZE_BYTES = 8; //in bytes
const bit<16> EGRESS_TS_SIZE_WORDS = 2; //in bytes

// INT INDIVIDUAL REPORT

//RepType
const bit<4> REP_TYPE_INNER_ONLY = 0;
const bit<4> REP_TYPE_INT        = 1;
const bit<4> REP_TYPE_IOAM       = 2;

//InType
const bit<4> INNER_TYPE_NONE     = 0;
const bit<4> INNER_TYPE_TLV      = 1;
const bit<4> INNER_TYPE_DSEP     = 2; //Domain specific extension data
const bit<4> INNER_TYPE_ETHERNET = 3;
const bit<4> INNER_TYPE_IPV4     = 4;
const bit<4> INNER_TYPE_IPV6     = 5;

// Length, in 4 byte words
const bit<8> IPV4_HEADER_LEN_WORDS     = 5; // 20 bytes
const bit<8> UDP_HEADER_LEN_WORDS      = 2; // 8 bytes
const bit<8> TCP_HEADER_LEN_WORDS      = 5; // 20 bytes
const bit<8> INT_SHIM_HEADER_LEN_WORDS = 1; // 4 bytes
const bit<8> INT_META_HEADER_LEN_WORDS = 3; // 12 bytes
const bit<8> INT_INDIV_REP_LEN_WORDS   = 1; // 4 bytes
const bit<8> METADATA_4_BYTE_AS_WORDS  = 1;
const bit<8> METADATA_8_BYTE_AS_WORDS  = 2;

const bit<6> HW_ID = 1;

//D, Dropped
const bit<1> PACKET_NOT_DROPPED_WL = 0;
const bit<1> PACKET_DROPPED_WL     = 1;
//Q, Congested Queue Association
const bit<1> NOT_RELATED_TO_A_CONGESTED_QUEUE = 0;
const bit<1> CONGESTED_QUEUE_RELATED          = 1;
// Tracked Flow Association
const bit<1> NOT_A_TRACKED_FLOW = 0;
const bit<1> TRACKED_FLOW       = 1;
// Intermediate Report
const bit<1> NOT_AN_INTERMEDIATE_REPORT = 0;
const bit<1> AN_INTERMEDIATE_REPORT     = 1;


//Others
const egressSpec_t port = 129;
const egressSpec_t CPU_PORT_0 = 64;
const egressSpec_t CPU_PORT_1 = 66;
const egressSpec_t CL1_PORT = 144;
const egressSpec_t CL2_PORT = 145;
const egressSpec_t R1_PORT = 48;
const egressSpec_t R4_PORT = 49;
