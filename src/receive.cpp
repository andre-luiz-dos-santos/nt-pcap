#include "receive.h"

#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <cstring>
#include <iostream>
#include <mutex>

#include "metrics.h"
#include "packet.h"
#include "secret.h"
#include "sender.h"

extern Secret secret;
extern Metrics metrics;
extern Sender sender;

void Receiver::open() {
    std::string err;
    char errbuf[PCAP_ERRBUF_SIZE];

    errbuf[0] = '\0';
    this->handle = pcap_open_live(this->dev.c_str(), BUFSIZ, 0, 100, errbuf);
    if (this->handle == nullptr) {
        throw std::runtime_error("Error opening device " + dev + ": " + errbuf);
    } else if (errbuf[0] != '\0') {
        std::cerr << "pcap_open_live: " << errbuf << std::endl;
    }

    this->datalink = pcap_datalink(this->handle);
    switch (this->datalink) {
    case DLT_RAW:
        this->iph_offset = 0;
        break;
    case DLT_EN10MB:
        this->iph_offset = 14;
        break;
    case DLT_LINUX_SLL:
        this->iph_offset = 16;
        break;
    case DLT_NULL:
    case DLT_LOOP:
        this->iph_offset = 4;
        break;
    case DLT_PPP:
        this->iph_offset = 4;
        break;
    default:
        err = "Unsupported datalink type: ";
        err += pcap_datalink_val_to_name(this->datalink);
        throw std::runtime_error(err);
    }

    bpf_program fp;
    char filter_exp[] = R"(
        inbound and (
            ip and (
                (tcp and tcp[20:4] = 0x54455354) or
                (udp and udp[8:4] = 0x54455354) or
                (icmp and icmp[8:4] = 0x54455354)
            ) or (
                ip6 and (
                    (tcp and ip6[60:4] = 0x54455354) or
                    (udp and ip6[48:4] = 0x54455354) or
                    (icmp6 and ip6[48:4] = 0x54455354)
                )
            )
        )
    )";
    if (pcap_compile(this->handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        err = "Error compiling filter: ";
        err += pcap_geterr(this->handle);
        throw std::system_error(errno, std::system_category(), err);
    }

    if (pcap_setfilter(this->handle, &fp) == -1) {
        err = "Error setting filter: ";
        err += pcap_geterr(this->handle);
        throw std::system_error(errno, std::system_category(), err);
    }

    pcap_freecode(&fp);
}

void Receiver::loop() {
    auto cb = [](u_char *user, const pcap_pkthdr *h, const u_char *bytes) {
        ((Receiver *)user)->receive(h, bytes);
    };
    pcap_loop(this->handle, 0, cb, (u_char *)this /* = user */);
    throw std::runtime_error("pcap_loop failed: " + std::string(pcap_geterr(this->handle)));
}

void Receiver::receive(const pcap_pkthdr *pkthdr, const u_char *packet) {
    int packet_len = pkthdr->caplen;
    int64_t received_timestamp_ms = (int64_t)pkthdr->ts.tv_sec * 1000 + pkthdr->ts.tv_usec / 1000;

#define SKIP(x)               \
    {                         \
        packet += x;          \
        packet_len -= x;      \
        if (packet_len < 0) { \
            return;           \
        }                     \
    }

    SKIP(this->iph_offset);

    uint8_t ip_version = (packet[0] >> 4) & 0x0F;
    switch (ip_version) {
    case 4: {
        auto iph = (iphdr *)packet;
        SKIP(sizeof(*iph));

        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->saddr, src_ip, sizeof(src_ip));

        int ttl = iph->ttl;

        switch (iph->protocol) {
        case IPPROTO_TCP: {
            auto tcph = (tcphdr *)packet;
            SKIP(sizeof(*tcph));

            auto pf = (PacketFormat *)packet;
            SKIP(sizeof(*pf));

            if (memcmp(pf->magic, "TEST", 4) != 0) {
                return;
            } else if (secret.verify(pf) == false) {
                return;
            }

            char *src_name = pf->src_name;
            src_name[MAX_NAME_SIZE - 1] = '\0';

            char *dst_name = pf->dst_name;
            dst_name[MAX_NAME_SIZE - 1] = '\0';

            int dst_port = ntohs(tcph->dest);

            auto found = sender.set_dst_ip4(dst_name, src_name, iph->saddr, pf->index_timestamp_ms);
            if (found == false) {
                break;
            }

            sender.set_dyn_dst_ip4(pf->other.src_name, pf->other.dst_name, pf->other.ip.v4, pf->other.index_timestamp_ms);

            metrics.add_received_point(
                pf->index_timestamp_ms,
                received_timestamp_ms - pf->sent_timestamp_ms,
                "IP4",
                "TCP",
                src_name,
                dst_name,
                src_ip,
                dst_port,
                ttl);

            break;
        }
        case IPPROTO_UDP: {
            auto udph = (udphdr *)packet;
            SKIP(sizeof(*udph));

            auto pf = (PacketFormat *)packet;
            SKIP(sizeof(*pf));

            if (memcmp(pf->magic, "TEST", 4) != 0) {
                return;
            } else if (secret.verify(pf) == false) {
                return;
            }

            char *src_name = pf->src_name;
            src_name[MAX_NAME_SIZE - 1] = '\0';

            char *dst_name = pf->dst_name;
            dst_name[MAX_NAME_SIZE - 1] = '\0';

            int dst_port = ntohs(udph->dest);

            auto found = sender.set_dst_ip4(dst_name, src_name, iph->saddr, pf->index_timestamp_ms);
            if (found == false) {
                break;
            }

            sender.set_dyn_dst_ip4(pf->other.src_name, pf->other.dst_name, pf->other.ip.v4, pf->other.index_timestamp_ms);

            metrics.add_received_point(
                pf->index_timestamp_ms,
                received_timestamp_ms - pf->sent_timestamp_ms,
                "IP4",
                "UDP",
                src_name,
                dst_name,
                src_ip,
                dst_port,
                ttl);

            break;
        }
        case IPPROTO_ICMP: {
            auto icmph = (icmphdr *)packet;
            SKIP(sizeof(*icmph));

            auto pf = (PacketFormat *)packet;
            SKIP(sizeof(*pf));

            if (memcmp(pf->magic, "TEST", 4) != 0) {
                return;
            } else if (secret.verify(pf) == false) {
                return;
            }

            char *src_name = pf->src_name;
            src_name[MAX_NAME_SIZE - 1] = '\0';

            char *dst_name = pf->dst_name;
            dst_name[MAX_NAME_SIZE - 1] = '\0';

            // Use ICMP sequence number as destination port.
            int dst_port = ntohs(icmph->un.echo.sequence);

            auto found = sender.set_dst_ip4(dst_name, src_name, iph->saddr, pf->index_timestamp_ms);
            if (found == false) {
                break;
            }

            sender.set_dyn_dst_ip4(pf->other.src_name, pf->other.dst_name, pf->other.ip.v4, pf->other.index_timestamp_ms);

            metrics.add_received_point(
                pf->index_timestamp_ms,
                received_timestamp_ms - pf->sent_timestamp_ms,
                "IP4",
                "ICMP",
                src_name,
                dst_name,
                src_ip,
                dst_port,
                ttl);

            break;
        }
        }
        break;
    }
    case 6: {
        auto iph = (ip6_hdr *)packet;
        SKIP(sizeof(*iph));

        char src_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &iph->ip6_src, src_ip, sizeof(src_ip));

        int ttl = iph->ip6_hlim;

        switch (iph->ip6_nxt) {
        case IPPROTO_TCP: {
            auto tcph = (tcphdr *)packet;
            SKIP(sizeof(*tcph));

            auto pf = (PacketFormat *)packet;
            SKIP(sizeof(*pf));

            if (memcmp(pf->magic, "TEST", 4) != 0) {
                return;
            } else if (secret.verify(pf) == false) {
                return;
            }

            char *src_name = pf->src_name;
            src_name[MAX_NAME_SIZE - 1] = '\0';

            char *dst_name = pf->dst_name;
            dst_name[MAX_NAME_SIZE - 1] = '\0';

            int dst_port = ntohs(tcph->dest);

            auto found = sender.set_dst_ip6(dst_name, src_name, iph->ip6_src.s6_addr, pf->index_timestamp_ms);
            if (found == false) {
                break;
            }

            sender.set_dyn_dst_ip6(pf->other.src_name, pf->other.dst_name, pf->other.ip.v6, pf->other.index_timestamp_ms);

            metrics.add_received_point(
                pf->index_timestamp_ms,
                received_timestamp_ms - pf->sent_timestamp_ms,
                "IP6",
                "TCP",
                src_name,
                dst_name,
                src_ip,
                dst_port,
                ttl);

            break;
        }
        case IPPROTO_UDP: {
            auto udph = (udphdr *)packet;
            SKIP(sizeof(*udph));

            auto pf = (PacketFormat *)packet;
            SKIP(sizeof(*pf));

            if (memcmp(pf->magic, "TEST", 4) != 0) {
                return;
            } else if (secret.verify(pf) == false) {
                return;
            }

            char *src_name = pf->src_name;
            src_name[MAX_NAME_SIZE - 1] = '\0';

            char *dst_name = pf->dst_name;
            dst_name[MAX_NAME_SIZE - 1] = '\0';

            int dst_port = ntohs(udph->dest);

            auto found = sender.set_dst_ip6(dst_name, src_name, iph->ip6_src.s6_addr, pf->index_timestamp_ms);
            if (found == false) {
                break;
            }

            sender.set_dyn_dst_ip6(pf->other.src_name, pf->other.dst_name, pf->other.ip.v6, pf->other.index_timestamp_ms);

            metrics.add_received_point(
                pf->index_timestamp_ms,
                received_timestamp_ms - pf->sent_timestamp_ms,
                "IP6",
                "UDP",
                src_name,
                dst_name,
                src_ip,
                dst_port,
                ttl);

            break;
        }
        case IPPROTO_ICMPV6: {
            auto icmph = (icmp6_hdr *)packet;
            SKIP(sizeof(*icmph));

            auto pf = (PacketFormat *)packet;
            SKIP(sizeof(*pf));

            if (memcmp(pf->magic, "TEST", 4) != 0) {
                return;
            } else if (secret.verify(pf) == false) {
                return;
            }

            char *src_name = pf->src_name;
            src_name[MAX_NAME_SIZE - 1] = '\0';

            char *dst_name = pf->dst_name;
            dst_name[MAX_NAME_SIZE - 1] = '\0';

            // Use ICMPv6 sequence number as destination port
            int dst_port = ntohs(icmph->icmp6_seq);

            auto found = sender.set_dst_ip6(dst_name, src_name, iph->ip6_src.s6_addr, pf->index_timestamp_ms);
            if (found == false) {
                break;
            }

            sender.set_dyn_dst_ip6(pf->other.src_name, pf->other.dst_name, pf->other.ip.v6, pf->other.index_timestamp_ms);

            metrics.add_received_point(
                pf->index_timestamp_ms,
                received_timestamp_ms - pf->sent_timestamp_ms,
                "IP6",
                "ICMP",
                src_name,
                dst_name,
                src_ip,
                dst_port,
                ttl);

            break;
        }
        }

        break;
    }
    default:
        std::cerr << "Unknown IP version: " << ip_version << std::endl;
        break;
    }
}
