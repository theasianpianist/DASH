#ifndef _SIRIUS_SERVICE_TUNNEL_P4_
#define _SIRIUS_SERVICE_TUNNEL_P4_

#include "dash_headers.p4"

action build_service_tunnel_v1_src_prefix(inout IPv6Address src_prefix,
                                          in bit<32> link_id,
                                          in bit<8> region_id,
                                          in bit<16> vnet_id,
                                          in bit<16> subnet_id) {
    src_prefix = 128w0xfde48dba << 96; /* base prefix for all v1 packets */
    src_prefix = src_prefix + ((bit<128>)link_id[16:1] << 80);
    src_prefix = src_prefix + ((bit<128>)region_id << 72);
    src_prefix = src_prefix + ((bit<128>)vnet_id << 48);
    src_prefix = src_prefix + ((bit<128>)subnet_id << 32);
}

action build_service_tunnel_v2_src_prefix(inout IPv6Address src_prefix,
                                          in bit<1> traffic_type,
                                          in bit<1> exfil_policy,
                                          in bit<32> link_id,
                                          in bit<8> region_id,
                                          in bit<16> vnet_id,
                                          in bit<16> subnet_id) {
    src_prefix = 128w0xfd << 120; /* base prefix for all v2 packets */
    // src_prefix = src_prefix + (1w0 << 119); /* encode ST v2 */
    src_prefix = src_prefix + ((bit<128>)traffic_type << 118);
    // src_prefix = src_prefix + (5w0 << 113); /* 5 reserved bits */
    src_prefix = src_prefix + ((bit<128>)exfil_policy << 112);
    src_prefix = src_prefix + ((bit<128>)link_id << 80);
    src_prefix = src_prefix + ((bit<128>)region_id << 72);
    src_prefix = src_prefix + ((bit<128>)vnet_id << 48);
    src_prefix = src_prefix + ((bit<128>)subnet_id << 32);
}

/* Encodes V4 in V6 */
action service_tunnel_encode(inout headers_t hdr,
                             in IPv6Address st_dst_prefix,
                             in IPv6Address st_src_prefix) {
    hdr.ipv6.setValid();
    hdr.ipv6.version = 6;
    hdr.ipv6.traffic_class = 0;
    hdr.ipv6.flow_label = 0;
    hdr.ipv6.payload_length = hdr.ipv4.total_len - IPV4_HDR_SIZE;
    hdr.ipv6.next_header = hdr.ipv4.protocol;
    hdr.ipv6.hop_limit = hdr.ipv4.ttl;
    hdr.ipv6.dst_addr = (IPv6Address)hdr.ipv4.dst_addr + st_dst_prefix;
    hdr.ipv6.src_addr = (IPv6Address)hdr.ipv4.src_addr + st_src_prefix;
    
    hdr.ipv4.setInvalid();
    hdr.ethernet.ether_type = IPV6_ETHTYPE;
}

/* Decodes V4 from V6 */
action service_tunnel_decode(inout headers_t hdr) {
    hdr.ipv4.setValid();
    hdr.ipv4.version = 4;
    hdr.ipv4.ihl = 5;
    hdr.ipv4.diffserv = 0;
    hdr.ipv4.total_len = hdr.ipv6.payload_length + IPV4_HDR_SIZE;
    hdr.ipv4.identification = 1;
    hdr.ipv4.flags = 0;
    hdr.ipv4.frag_offset = 0;
    hdr.ipv4.protocol = hdr.ipv6.next_header;
    hdr.ipv4.ttl = hdr.ipv6.hop_limit;
    hdr.ipv4.hdr_checksum = 0;

    hdr.ipv6.setInvalid();
    hdr.ethernet.ether_type = IPV4_ETHTYPE;
}

#endif /* _SIRIUS_SERVICE_TUNNEL_P4_ */
