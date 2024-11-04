#include "packet.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iostream>

#include "checksum.h"
#include "secret.h"
#include "time.h"

extern Secret secret;

void Packet::init(int size) {
    this->size = size;
    this->vector.resize(size);
    auto buf = this->vector.data();
    memset(buf, 0, size);
    this->a.ptr = buf;
}

void Packet::init_ip4() {
    a.ip4->ihl = 5;
    a.ip4->version = 4;
    a.ip4->tot_len = htons(this->size);
    a.ip4->id = 1;
    a.ip4->ttl = 255;
    this->b.ptr = a.ip4 + 1;
}

void Packet::init_ip6() {
    a.ip6->ip6_vfc = 0x60;
    a.ip6->ip6_plen = htons(size - sizeof(*a.ip6));
    a.ip6->ip6_hlim = 255;
    this->b.ptr = a.ip6 + 1;
}

void tcp_common(tcphdr *tcph) {
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 0;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 1;
    tcph->urg = 0;
    tcph->window = htons(5840);
    tcph->urg_ptr = 0;
}

void Packet::init_tcp4() {
    a.ip4->protocol = IPPROTO_TCP;
    tcp_common(b.tcp);
    this->c.ptr = b.tcp + 1;
}

void Packet::init_tcp6() {
    a.ip6->ip6_nxt = IPPROTO_TCP;
    tcp_common(b.tcp);
    this->c.ptr = b.tcp + 1;
}

void Packet::init_udp4() {
    a.ip4->protocol = IPPROTO_UDP;
    b.udp->len = htons(this->size - sizeof(*a.ip4));
    this->c.ptr = b.udp + 1;
}

void Packet::init_udp6() {
    a.ip6->ip6_nxt = IPPROTO_UDP;
    b.udp->len = htons(this->size - sizeof(*a.ip6));
    this->c.ptr = b.udp + 1;
}

void Packet::init_icmp4() {
    a.ip4->protocol = IPPROTO_ICMP;
    b.icmp->type = ICMP_ECHOREPLY;
    b.icmp->code = 0;
    b.icmp->checksum = 0;
    b.icmp->un.echo.id = 0;
    this->c.ptr = b.icmp + 1;
}

void Packet::init_icmp6() {
    a.ip6->ip6_nxt = IPPROTO_ICMPV6;
    b.icmp6->icmp6_type = ICMP6_ECHO_REPLY;
    b.icmp6->icmp6_code = 0;
    b.icmp6->icmp6_cksum = 0;
    b.icmp6->icmp6_id = 0;
    this->c.ptr = b.icmp6 + 1;
}

void Packet::init_pf() {
    memcpy(c.pf->magic, "TEST", 4);
}

void Packet::ip4_addrs(uint32_t src_ip, uint32_t dst_ip) {
    a.ip4->saddr = src_ip;
    a.ip4->daddr = dst_ip;
}

void Packet::ip6_addrs(const char src_ip[16], const char dst_ip[16]) {
    memcpy(&a.ip6->ip6_src, src_ip, 16);
    memcpy(&a.ip6->ip6_dst, dst_ip, 16);
}

void Packet::tcp_ports(uint16_t src_port, uint16_t dst_port) {
    b.tcp->source = htons(src_port);
    b.tcp->dest = htons(dst_port);
}

void Packet::udp_ports(uint16_t src_port, uint16_t dst_port) {
    b.udp->source = htons(src_port);
    b.udp->dest = htons(dst_port);
}

void Packet::icmp4_sequence(uint16_t seq) {
    b.icmp->un.echo.sequence = htons(seq);
}

void Packet::icmp6_sequence(uint16_t seq) {
    b.icmp6->icmp6_seq = htons(seq);
}

void Packet::pf_names(int64_t index_timestamp_ms, const char src_name[MAX_NAME_SIZE + 1], const char dst_name[MAX_NAME_SIZE + 1]) {
    c.pf->index_timestamp_ms = index_timestamp_ms;
    memcpy(c.pf->src_name, src_name, MAX_NAME_SIZE + 1);
    memcpy(c.pf->dst_name, dst_name, MAX_NAME_SIZE + 1);

    int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(get_realtime_clock()).count();
    c.pf->sent_timestamp_ms = now;
}

void Packet::checksum_tcp4() {
    secret.sign(c.pf);
    compute_ip_checksum(a.ip4);
    compute_tcp_checksum(a.ip4, (unsigned short *)b.tcp);
}

void Packet::checksum_tcp6() {
    secret.sign(c.pf);
    b.tcp->check = htons(compute_tcp_checksum_ipv6(a.ip6, b.tcp, c.pf, this->size - sizeof(*a.ip6) - sizeof(*b.tcp)));
}

void Packet::checksum_udp4() {
    secret.sign(c.pf);
    compute_ip_checksum(a.ip4);
    // UDP checksum is optional, so don't waste CPU on it.
    // compute_udp_checksum(iph, (unsigned short *)udph);
    b.udp->check = 0;
}

void Packet::checksum_udp6() {
    secret.sign(c.pf);
    b.udp->check = htons(compute_udp_checksum_ipv6(a.ip6, b.udp, c.pf, this->size - sizeof(*a.ip6) - sizeof(*b.udp)));
}

void Packet::checksum_icmp4() {
    secret.sign(c.pf);
    compute_ip_checksum(a.ip4);
    compute_icmp_checksum(b.icmp, this->size - sizeof(*a.ip4));
}

void Packet::checksum_icmp6() {
    secret.sign(c.pf);
    b.icmp6->icmp6_cksum = htons(compute_icmpv6_checksum_ipv6(a.ip6, b.icmp6, c.pf, this->size - sizeof(*a.ip6) - sizeof(*b.icmp6)));
}
