#include "sender.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/uio.h>

#include <algorithm>
#include <cstring>
#include <iostream>

#include "checksum.h"
#include "metrics.h"
#include "packet.h"
#include "secret.h"
#include "time.h"

extern Secret secret;
extern Metrics metrics;

void Sender::open() {
    this->sock4 = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (this->sock4 < 0) {
        throw std::system_error(errno, std::system_category(), "Error creating IPv4 socket");
    }
    this->sock6 = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
    if (this->sock6 < 0) {
        throw std::system_error(errno, std::system_category(), "Error creating IPv6 socket");
    }
}

void Sender::loop() {
    std::vector<char> packet4(this->packet_size);
    std::vector<char> packet6(this->packet_size);

    auto packet4_buf = packet4.data();
    auto packet6_buf = packet6.data();

    memset(packet4_buf, 0, this->packet_size);
    memset(packet6_buf, 0, this->packet_size);

    {
        auto iph = (struct iphdr *)packet4_buf;
        memset(iph, 0, sizeof(*iph));
        iph->ihl = 5;
        iph->version = 4;
        iph->tot_len = htons(this->packet_size);
        iph->id = htons(rand());
        iph->ttl = 255;
    }

    {
        auto iph = (struct ip6_hdr *)packet6_buf;
        memset(iph, 0, sizeof(*iph));
        iph->ip6_vfc = 0x60;
        iph->ip6_plen = htons(this->packet_size - sizeof(*iph));
        iph->ip6_hlim = 255;
    }

    struct sockaddr_in dest_addr4;
    memset(&dest_addr4, 0, sizeof(dest_addr4));
    dest_addr4.sin_family = AF_INET;

    struct sockaddr_in6 dest_addr6;
    memset(&dest_addr6, 0, sizeof(dest_addr6));
    dest_addr6.sin6_family = AF_INET6;

    static const char ipv6_zeros[16] = {0};

    Ticker tick(this->interval_ms * 1000);  // microseconds

    for (int port_idx = 0;; port_idx++) {
        if (port_idx >= this->ports_count) {
            port_idx = 0;
        }
        const int curr_src_port = this->src_port + port_idx;
        const int curr_dst_port = this->dst_port + port_idx;

        tick.sleep();
        time_t index_timestamp_ms = tick.timestamp / 1000;

        for (const auto &[_, path] : this->paths4) {
            if (path.src_addr == 0 || path.dst_addr == 0) {
                continue;
            }

            // sendto address.
            dest_addr4.sin_addr.s_addr = path.dst_addr;

            {  // TCP packet
                char *packet = packet4_buf;

                auto iph = (struct iphdr *)packet;
                packet += sizeof(*iph);

                iph->protocol = IPPROTO_TCP;
                iph->saddr = path.src_addr;
                iph->daddr = path.dst_addr;
                iph->check = 0;

                auto tcph = (struct tcphdr *)packet;
                packet += sizeof(*tcph);

                tcph->source = htons(curr_src_port);
                tcph->dest = htons(curr_dst_port);
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
                tcph->check = 0;
                tcph->urg_ptr = 0;

                auto pf = (PacketFormat *)packet;
                packet += sizeof(*pf);

                memcpy(pf->magic, "TEST", 4);
                pf->index_timestamp_ms = index_timestamp_ms;
                pf->sent_timestamp_ms = get_realtime_clock() / 1000;
                memcpy(pf->src_name, path.src_name, MAX_NAME_SIZE + 1);
                memcpy(pf->dst_name, path.dst_name, MAX_NAME_SIZE + 1);

                secret.sign(pf);

                compute_ip_checksum(iph);
                compute_tcp_checksum(iph, (unsigned short *)tcph);

                if (sendto(this->sock4, packet4_buf, this->packet_size, 0, (struct sockaddr *)&dest_addr4, sizeof(dest_addr4)) < 0) {
                    throw std::system_error(errno, std::system_category(), "sendto(IPv4/TCP) failed");
                }
            }

            {  // UDP packet
                char *packet = packet4_buf;

                auto iph = (struct iphdr *)packet;
                packet += sizeof(*iph);

                iph->protocol = IPPROTO_UDP;
                iph->saddr = path.src_addr;
                iph->daddr = path.dst_addr;
                iph->check = 0;

                auto udph = (struct udphdr *)packet;
                packet += sizeof(*udph);

                udph->source = htons(curr_src_port);
                udph->dest = htons(curr_dst_port);
                udph->len = htons(this->packet_size - sizeof(*iph));
                udph->check = 0;

                auto pf = (PacketFormat *)packet;
                packet += sizeof(*pf);

                memcpy(pf->magic, "TEST", 4);
                pf->index_timestamp_ms = index_timestamp_ms;
                pf->sent_timestamp_ms = get_realtime_clock() / 1000;
                memcpy(pf->src_name, path.src_name, MAX_NAME_SIZE + 1);
                memcpy(pf->dst_name, path.dst_name, MAX_NAME_SIZE + 1);

                secret.sign(pf);

                compute_ip_checksum(iph);
                // UDP checksum is optional, so don't waste CPU on it.
                // compute_udp_checksum(iph, (unsigned short *)udph);

                if (sendto(this->sock4, packet4_buf, this->packet_size, 0, (struct sockaddr *)&dest_addr4, sizeof(dest_addr4)) < 0) {
                    throw std::system_error(errno, std::system_category(), "sendto(IPv4/UDP) failed");
                }
            }

            {  // ICMP packet
                char *packet = packet4_buf;

                auto iph = (struct iphdr *)packet;
                packet += sizeof(*iph);

                iph->protocol = IPPROTO_ICMP;
                iph->saddr = path.src_addr;
                iph->daddr = path.dst_addr;
                iph->check = 0;

                auto icmph = (struct icmphdr *)packet;
                packet += sizeof(*icmph);

                icmph->type = ICMP_ECHOREPLY;
                icmph->code = 0;
                icmph->checksum = 0;
                icmph->un.echo.id = 0;  // htons(getpid());
                icmph->un.echo.sequence = htons(curr_dst_port);

                auto pf = (PacketFormat *)packet;
                packet += sizeof(*pf);

                memcpy(pf->magic, "TEST", 4);
                pf->index_timestamp_ms = index_timestamp_ms;
                pf->sent_timestamp_ms = get_realtime_clock() / 1000;
                memcpy(pf->src_name, path.src_name, MAX_NAME_SIZE + 1);
                memcpy(pf->dst_name, path.dst_name, MAX_NAME_SIZE + 1);

                secret.sign(pf);

                compute_ip_checksum(iph);
                compute_icmp_checksum(icmph, this->packet_size - sizeof(*iph));

                if (sendto(this->sock4, packet4_buf, this->packet_size, 0, (struct sockaddr *)&dest_addr4, sizeof(dest_addr4)) < 0) {
                    throw std::system_error(errno, std::system_category(), "sendto(IPv4/ICMP) failed");
                }
            }
        }

        for (const auto &[_, path] : this->paths6) {
            if (memcmp(path.src_addr, ipv6_zeros, 16) == 0 || memcmp(path.dst_addr, ipv6_zeros, 16) == 0) {
                continue;
            }

            // sendto address.
            memcpy(&dest_addr6.sin6_addr, path.dst_addr, 16);

            {  // TCP packet
                char *packet = packet6_buf;

                auto iph = (struct ip6_hdr *)packet;
                packet += sizeof(*iph);

                iph->ip6_nxt = IPPROTO_TCP;
                memcpy(&iph->ip6_src, path.src_addr, 16);
                memcpy(&iph->ip6_dst, path.dst_addr, 16);

                auto tcph = (struct tcphdr *)packet;
                packet += sizeof(*tcph);

                tcph->source = htons(curr_src_port);
                tcph->dest = htons(curr_dst_port);
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
                tcph->check = 0;
                tcph->urg_ptr = 0;

                auto pf = (PacketFormat *)packet;
                packet += sizeof(*pf);

                memcpy(pf->magic, "TEST", 4);
                pf->index_timestamp_ms = index_timestamp_ms;
                pf->sent_timestamp_ms = get_realtime_clock() / 1000;
                memcpy(pf->src_name, path.src_name, MAX_NAME_SIZE + 1);
                memcpy(pf->dst_name, path.dst_name, MAX_NAME_SIZE + 1);

                secret.sign(pf);

                tcph->check = htons(compute_tcp_checksum_ipv6(iph, tcph, pf, this->packet_size - sizeof(*iph) - sizeof(*tcph)));

                if (sendto(this->sock6, packet6_buf, this->packet_size, 0, (struct sockaddr *)&dest_addr6, sizeof(dest_addr6)) < 0) {
                    throw std::system_error(errno, std::system_category(), "sendto(IPv6/TCP) failed");
                }
            }

            {  // UDP packet
                char *packet = packet6_buf;

                auto iph = (struct ip6_hdr *)packet;
                packet += sizeof(*iph);

                iph->ip6_nxt = IPPROTO_UDP;
                memcpy(&iph->ip6_src, path.src_addr, 16);
                memcpy(&iph->ip6_dst, path.dst_addr, 16);

                auto udph = (struct udphdr *)packet;
                packet += sizeof(*udph);

                udph->source = htons(curr_src_port);
                udph->dest = htons(curr_dst_port);
                udph->len = htons(this->packet_size - sizeof(*iph));
                udph->check = 0;

                auto pf = (PacketFormat *)packet;
                packet += sizeof(*pf);

                memcpy(pf->magic, "TEST", 4);
                pf->index_timestamp_ms = index_timestamp_ms;
                pf->sent_timestamp_ms = get_realtime_clock() / 1000;
                memcpy(pf->src_name, path.src_name, MAX_NAME_SIZE + 1);
                memcpy(pf->dst_name, path.dst_name, MAX_NAME_SIZE + 1);

                secret.sign(pf);

                udph->check = htons(compute_udp_checksum_ipv6(iph, udph, pf, this->packet_size - sizeof(*iph) - sizeof(*udph)));

                if (sendto(this->sock6, packet6_buf, this->packet_size, 0, (struct sockaddr *)&dest_addr6, sizeof(dest_addr6)) < 0) {
                    throw std::system_error(errno, std::system_category(), "sendto(IPv6/UDP) failed");
                }
            }

            {  // ICMPv6 packet
                char *packet = packet6_buf;

                auto iph = (struct ip6_hdr *)packet;
                packet += sizeof(*iph);

                iph->ip6_nxt = IPPROTO_ICMPV6;
                memcpy(&iph->ip6_src, path.src_addr, 16);
                memcpy(&iph->ip6_dst, path.dst_addr, 16);

                auto icmph = (struct icmp6_hdr *)packet;
                packet += sizeof(*icmph);

                icmph->icmp6_type = ICMP6_ECHO_REPLY;
                icmph->icmp6_code = 0;
                icmph->icmp6_cksum = 0;
                icmph->icmp6_id = 0;  // htons(getpid());
                icmph->icmp6_seq = htons(curr_dst_port);

                auto pf = (PacketFormat *)packet;
                packet += sizeof(*pf);

                memcpy(pf->magic, "TEST", 4);
                pf->index_timestamp_ms = index_timestamp_ms;
                pf->sent_timestamp_ms = get_realtime_clock() / 1000;
                memcpy(pf->src_name, path.src_name, MAX_NAME_SIZE + 1);
                memcpy(pf->dst_name, path.dst_name, MAX_NAME_SIZE + 1);

                secret.sign(pf);

                icmph->icmp6_cksum = htons(compute_icmpv6_checksum_ipv6(iph, icmph, pf, this->packet_size - sizeof(*iph) - sizeof(*icmph)));

                if (sendto(this->sock6, packet6_buf, this->packet_size, 0, (struct sockaddr *)&dest_addr6, sizeof(dest_addr6)) < 0) {
                    throw std::system_error(errno, std::system_category(), "sendto(IPv6/ICMPv6) failed");
                }
            }
        }

        // Add metrics outside the loop that sends packets.
        for (const auto &[_, path] : this->paths4) {
            if (path.src_addr == 0 || path.dst_addr == 0) {
                continue;
            }
            metrics.add_sent_point(
                index_timestamp_ms,
                "IP4",
                path.src_name,
                path.dst_name,
                curr_dst_port);
        }
        for (const auto &[_, path] : this->paths6) {
            if (memcmp(path.src_addr, ipv6_zeros, 16) == 0 || memcmp(path.dst_addr, ipv6_zeros, 16) == 0) {
                continue;
            }
            metrics.add_sent_point(
                index_timestamp_ms,
                "IP6",
                path.src_name,
                path.dst_name,
                curr_dst_port);
        }
    }
}

void Sender::add_path4(const char *src_name, const char *dst_name, Path4 &path) {
    std::array<char, (MAX_NAME_SIZE + 1) * 2> key;
    memset(key.data(), 0, key.size());
    strcpy(key.data(), src_name);
    strcpy(key.data() + MAX_NAME_SIZE + 1, dst_name);

    if (this->paths4.find(key) != this->paths4.end()) {
        throw std::runtime_error("Path from " + std::string(src_name) + " to " + std::string(dst_name) + " already exists in paths4");
    }

    this->paths4[key] = path;
}

void Sender::add_path6(const char *src_name, const char *dst_name, Path6 &path) {
    std::array<char, (MAX_NAME_SIZE + 1) * 2> key;
    memset(key.data(), 0, key.size());
    strcpy(key.data(), src_name);
    strcpy(key.data() + MAX_NAME_SIZE + 1, dst_name);

    if (this->paths6.find(key) != this->paths6.end()) {
        throw std::runtime_error("Path from " + std::string(src_name) + " to " + std::string(dst_name) + " already exists in paths6");
    }

    this->paths6[key] = path;
}

/**
 * Set remote IP address for path src_name -> dst_name.
 * Returns true if the path was found, false otherwise.
 *
 * There is a data race here:
 * The sender thread reads while the receiver thread writes to `dst_addr`.
 */
bool Sender::set_remote_ip4(const char *src_name, const char *dst_name, uint32_t addr) {
    // Build the path key.
    std::array<char, (MAX_NAME_SIZE + 1) * 2> key;
    memcpy(key.data(), src_name, MAX_NAME_SIZE + 1);
    memcpy(key.data() + MAX_NAME_SIZE + 1, dst_name, MAX_NAME_SIZE + 1);

    // Search for the path.
    auto it = this->paths4.find(key);
    if (it == this->paths4.end()) {
        return false;
    }

    // Skip static or unchanged paths.
    auto &path = it->second;
    if (path.dst_addr_dyn == false) {
        return true;
    } else if (path.dst_addr == addr) {
        return true;
    }

    // Update path's destination address.
    path.dst_addr = addr;
    std::cout << "Destination for path " << src_name << " -> " << dst_name << " updated to " << inet_ntoa({addr}) << std::endl;

    return true;
}

/**
 * Set remote IP address for path src_name -> dst_name.
 * Returns true if the path was found, false otherwise.
 *
 * There is a data race here:
 * The sender thread reads while the receiver thread writes to `dst_addr`.
 */
bool Sender::set_remote_ip6(const char *src_name, const char *dst_name, const void *addr) {
    // Build the path key.
    std::array<char, (MAX_NAME_SIZE + 1) * 2> key;
    memcpy(key.data(), src_name, MAX_NAME_SIZE + 1);
    memcpy(key.data() + MAX_NAME_SIZE + 1, dst_name, MAX_NAME_SIZE + 1);

    // Search for the path.
    auto it = this->paths6.find(key);
    if (it == this->paths6.end()) {
        return false;
    }

    // Skip static or unchanged paths.
    auto &path = it->second;
    if (path.dst_addr_dyn == false) {
        return true;
    } else if (memcmp(path.dst_addr, addr, 16) == 0) {
        return true;
    }

    // Update path's destination address.
    memcpy(path.dst_addr, addr, 16);

    // Log the path's IP change.
    char ip[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, addr, ip, INET6_ADDRSTRLEN);
    std::cout << "Destination for path " << src_name << " -> " << dst_name << " updated to " << ip << std::endl;

    return true;
}
