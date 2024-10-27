// https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a

#include "checksum.h"

#include <netinet/icmp6.h>
#include <netinet/ip6.h>

#include <cstring>

static unsigned short compute_checksum(unsigned short *addr, unsigned int count) {
    unsigned long sum = 0;
    while (count > 1) {
        sum += *addr++;
        count -= 2;
    }
    // if any bytes left, pad the bytes and add
    if (count > 0) {
        sum += ((*addr) & htons(0xFF00));
    }
    // Fold sum to 16 bits: add carrier to result
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // one's complement
    sum = ~sum;
    return ((unsigned short)sum);
}

void compute_ip_checksum(struct iphdr *iph) {
    iph->check = 0;
    iph->check = compute_checksum((unsigned short *)iph, iph->ihl << 2);
}

void compute_icmp_checksum(struct icmphdr *icmph, unsigned int icmp_size) {
    icmph->checksum = 0;
    icmph->checksum = compute_checksum((unsigned short *)icmph, icmp_size);
}

void compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload) {
    unsigned long sum = 0;
    unsigned short tcpLen = ntohs(pIph->tot_len) - (pIph->ihl << 2);
    struct tcphdr *tcphdrp = (struct tcphdr *)(ipPayload);
    // add the pseudo header
    // the source ip
    sum += (pIph->saddr >> 16) & 0xFFFF;
    sum += (pIph->saddr) & 0xFFFF;
    // the dest ip
    sum += (pIph->daddr >> 16) & 0xFFFF;
    sum += (pIph->daddr) & 0xFFFF;
    // protocol and reserved: 6
    sum += htons(IPPROTO_TCP);
    // the length
    sum += htons(tcpLen);

    // add the IP payload
    // initialize checksum to 0
    tcphdrp->check = 0;
    while (tcpLen > 1) {
        sum += *ipPayload++;
        tcpLen -= 2;
    }
    // if any bytes left, pad the bytes and add
    if (tcpLen > 0) {
        // printf("+++++++++++padding, %dn", tcpLen);
        sum += ((*ipPayload) & htons(0xFF00));
    }
    // Fold 32-bit sum to 16 bits: add carrier to result
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;
    // set computation result
    tcphdrp->check = (unsigned short)sum;
}

/* set tcp checksum: given IP header and UDP datagram */
void compute_udp_checksum(struct iphdr *pIph, unsigned short *ipPayload) {
    unsigned long sum = 0;
    struct udphdr *udphdrp = (struct udphdr *)(ipPayload);
    unsigned short udpLen = htons(udphdrp->len);
    // printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~udp len=%dn", udpLen);
    // add the pseudo header
    // printf("add pseudo headern");
    // the source ip
    sum += (pIph->saddr >> 16) & 0xFFFF;
    sum += (pIph->saddr) & 0xFFFF;
    // the dest ip
    sum += (pIph->daddr >> 16) & 0xFFFF;
    sum += (pIph->daddr) & 0xFFFF;
    // protocol and reserved: 17
    sum += htons(IPPROTO_UDP);
    // the length
    sum += udphdrp->len;

    // add the IP payload
    // printf("add ip payloadn");
    // initialize checksum to 0
    udphdrp->check = 0;
    while (udpLen > 1) {
        sum += *ipPayload++;
        udpLen -= 2;
    }
    // if any bytes left, pad the bytes and add
    if (udpLen > 0) {
        // printf("+++++++++++++++padding: %dn", udpLen);
        sum += ((*ipPayload) & htons(0xFF00));
    }
    // Fold sum to 16 bits: add carrier to result
    // printf("add carriern");
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    // printf("one's complementn");
    sum = ~sum;
    // set computation result
    udphdrp->check = ((unsigned short)sum == 0x0000) ? 0xFFFF : (unsigned short)sum;
}

uint16_t compute_tcp_checksum_ipv6(const void *ip_void, const void *tcp_void, const void *payload_void, int payload_len) {
    auto ip6h = (const struct ip6_hdr *)ip_void;
    auto tcph = (const struct tcphdr *)tcp_void;
    auto payload = (const uint8_t *)payload_void;

    // TCP pseudo-header for IPv6
    struct {
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t tcp_length;
        uint8_t zeros[3];
        uint8_t next_header;
    } pseudo_header;

    // Fill pseudo-header
    memcpy(&pseudo_header.src, &ip6h->ip6_src, sizeof(struct in6_addr));
    memcpy(&pseudo_header.dst, &ip6h->ip6_dst, sizeof(struct in6_addr));
    pseudo_header.tcp_length = htonl(ntohs(ip6h->ip6_plen));
    memset(pseudo_header.zeros, 0, sizeof(pseudo_header.zeros));
    pseudo_header.next_header = ip6h->ip6_nxt;

    // Calculate checksum
    uint32_t sum = 0;
    uint16_t *ptr;

    // Add pseudo-header
    ptr = (uint16_t *)&pseudo_header;
    for (size_t i = 0; i < sizeof(pseudo_header) / 2; i++) {
        sum += ntohs(ptr[i]);
    }

    // Add TCP header (excluding checksum field)
    ptr = (uint16_t *)tcph;
    for (size_t i = 0; i < sizeof(struct tcphdr) / 2; i++) {
        if (i != 8) {  // Skip checksum field
            sum += ntohs(ptr[i]);
        }
    }

    // Add payload
    ptr = (uint16_t *)payload;
    for (int i = 0; i < payload_len / 2; i++) {
        sum += ntohs(ptr[i]);
    }

    // Add last byte if payload_len is odd
    if (payload_len & 1) {
        sum += ntohs(((uint16_t)payload[payload_len - 1]) << 8);
    }

    // Fold 32-bit sum into 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

uint16_t compute_udp_checksum_ipv6(const void *ip_void, const void *udp_void, const void *payload_void, int payload_len) {
    auto ip6h = (const struct ip6_hdr *)ip_void;
    auto udph = (const struct udphdr *)udp_void;
    auto payload = (const uint8_t *)payload_void;

    // UDP pseudo-header for IPv6
    struct {
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t udp_length;
        uint8_t zeros[3];
        uint8_t next_header;
    } pseudo_header;

    // Fill pseudo-header
    memcpy(&pseudo_header.src, &ip6h->ip6_src, sizeof(struct in6_addr));
    memcpy(&pseudo_header.dst, &ip6h->ip6_dst, sizeof(struct in6_addr));
    pseudo_header.udp_length = htonl(ntohs(udph->len));
    memset(pseudo_header.zeros, 0, sizeof(pseudo_header.zeros));
    pseudo_header.next_header = IPPROTO_UDP;

    // Calculate checksum
    uint32_t sum = 0;
    uint16_t *ptr;

    // Add pseudo-header
    ptr = (uint16_t *)&pseudo_header;
    for (size_t i = 0; i < sizeof(pseudo_header) / 2; i++) {
        sum += ntohs(ptr[i]);
    }

    // Add UDP header (excluding checksum field)
    ptr = (uint16_t *)udph;
    for (size_t i = 0; i < sizeof(struct udphdr) / 2; i++) {
        if (i != 3) {  // Skip checksum field
            sum += ntohs(ptr[i]);
        }
    }

    // Add payload
    ptr = (uint16_t *)payload;
    for (int i = 0; i < payload_len / 2; i++) {
        sum += ntohs(ptr[i]);
    }

    // Add last byte if payload_len is odd
    if (payload_len & 1) {
        sum += ntohs(((uint16_t)payload[payload_len - 1]) << 8);
    }

    // Fold 32-bit sum into 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // UDP checksum of 0 must be changed to 0xFFFF
    uint16_t checksum = ~sum;
    return checksum == 0 ? 0xFFFF : checksum;
}

uint16_t compute_icmpv6_checksum_ipv6(const void *ip_void, const void *icmph_void, const void *payload_void, int payload_len) {
    auto ip6h = (const struct ip6_hdr *)ip_void;
    auto icmp6h = (const struct icmp6_hdr *)icmph_void;
    auto payload = (const uint8_t *)payload_void;

    // ICMPv6 pseudo-header
    struct {
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t icmpv6_length;
        uint8_t zeros[3];
        uint8_t next_header;
    } pseudo_header;

    // Fill pseudo-header
    memcpy(&pseudo_header.src, &ip6h->ip6_src, sizeof(struct in6_addr));
    memcpy(&pseudo_header.dst, &ip6h->ip6_dst, sizeof(struct in6_addr));
    // ICMPv6 length is the size of ICMPv6 header plus payload
    pseudo_header.icmpv6_length = htonl(sizeof(struct icmp6_hdr) + payload_len);
    memset(pseudo_header.zeros, 0, sizeof(pseudo_header.zeros));
    pseudo_header.next_header = IPPROTO_ICMPV6;

    // Calculate checksum
    uint32_t sum = 0;
    uint16_t *ptr;

    // Add pseudo-header
    ptr = (uint16_t *)&pseudo_header;
    for (size_t i = 0; i < sizeof(pseudo_header) / 2; i++) {
        sum += ntohs(ptr[i]);
    }

    // Add ICMPv6 header (including the checksum field as 0)
    ptr = (uint16_t *)icmp6h;
    for (size_t i = 0; i < sizeof(struct icmp6_hdr) / 2; i++) {
        if (i != 2) {  // Skip checksum field (at offset 4 bytes, or word 2)
            sum += ntohs(ptr[i]);
        }
    }

    // Add payload
    ptr = (uint16_t *)payload;
    for (int i = 0; i < payload_len / 2; i++) {
        sum += ntohs(ptr[i]);
    }

    // Add last byte if payload_len is odd
    if (payload_len & 1) {
        sum += ntohs(((uint16_t)payload[payload_len - 1]) << 8);
    }

    // Fold 32-bit sum into 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}
