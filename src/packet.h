#ifndef PACKET_H
#define PACKET_H

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <openssl/md5.h>

#include <cstdint>
#include <vector>

const int MAX_NAME_SIZE = 7;

struct PacketFormat {
    char magic[4];
    uint32_t unused;
    int64_t index_timestamp_ms;
    int64_t sent_timestamp_ms;
    char src_name[MAX_NAME_SIZE + 1];
    char dst_name[MAX_NAME_SIZE + 1];

    // Has to be the last field in the struct for Secret::sign to work.
    char hash[MD5_DIGEST_LENGTH];
} __attribute__((packed));

class Packet {
private:
    union ip {
        void *ptr;
        iphdr *ip4;
        ip6_hdr *ip6;
    } a;
    union ip_payload {
        void *ptr;
        tcphdr *tcp;
        udphdr *udp;
        icmphdr *icmp;
        icmp6_hdr *icmp6;
    } b;
    union c {
        void *ptr;
        PacketFormat *pf;
    } c;

public:
    int size;
    std::vector<char> vector;

    void init(int size);

    void init_ip4();
    void init_ip6();

    void init_tcp4();
    void init_tcp6();

    void init_udp4();
    void init_udp6();

    void init_icmp4();
    void init_icmp6();

    void init_pf();

    void ip4_addrs(uint32_t src_ip, uint32_t dst_ip);
    void ip6_addrs(const char src_ip[16], const char dst_ip[16]);

    void tcp_ports(uint16_t src_port, uint16_t dst_port);
    void udp_ports(uint16_t src_port, uint16_t dst_port);

    void icmp4_sequence(uint16_t seq);
    void icmp6_sequence(uint16_t seq);

    void checksum_tcp4();
    void checksum_tcp6();

    void checksum_udp4();
    void checksum_udp6();

    void checksum_icmp4();
    void checksum_icmp6();

    void pf_names(int64_t index_timestamp_ms, const char src_name[MAX_NAME_SIZE + 1], const char dst_name[MAX_NAME_SIZE + 1]);
};

#endif
