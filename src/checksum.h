#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

void compute_ip_checksum(struct iphdr *iph);
void compute_icmp_checksum(struct icmphdr *icmph, unsigned int icmp_size);
void compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload);
void compute_udp_checksum(struct iphdr *pIph, unsigned short *ipPayload);

uint16_t compute_tcp_checksum_ipv6(const void *ip_void, const void *tcp_void, const void *payload_void, int payload_len);
uint16_t compute_udp_checksum_ipv6(const void *ip_void, const void *udp_void, const void *payload_void, int payload_len);
uint16_t compute_icmpv6_checksum_ipv6(const void *ip_void, const void *icmph_void, const void *payload_void, int payload_len);

#endif
