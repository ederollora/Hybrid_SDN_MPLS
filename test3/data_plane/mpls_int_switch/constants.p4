const bit<16> ETHERTYPE_ARP  = 0x0806;
const bit<16> ETHERTYPE_VLAN = 0x8100;
const bit<16> ETHERTYPE_MPLS = 0x8847;
const bit<16> ETHERTYPE_IPV4 = 0x0800;

const bit<8>  IPPROTO_ICMP   = 0x01;
const bit<8>  IPPROTO_IPv4   = 0x04;
const bit<8>  IPPROTO_TCP   = 0x06;
const bit<8>  IPPROTO_UDP   = 0x11;

const bit<6>  DSCP_INT = 0x17;

const egressSpec_t port = 129;
const egressSpec_t CPU_PORT_0 = 64;
const egressSpec_t CPU_PORT_1 = 66;
const egressSpec_t CL1_PORT = 144;
const egressSpec_t CL2_PORT = 145;
const egressSpec_t R1_PORT = 48;
const egressSpec_t R4_PORT = 49;


/* Table Sizes */
const int IPV4_HOST_SIZE = 65536;
const int IPV4_LPM_SIZE  = 12288;
