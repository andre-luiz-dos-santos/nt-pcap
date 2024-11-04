#include "sender.h"

#include <algorithm>
#include <cstring>
#include <iostream>

#include "checksum.h"
#include "metrics.h"
#include "packet.h"
#include "time.h"

extern Metrics metrics;

constexpr uint64_t to_ms(std::chrono::nanoseconds ns) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(ns).count();
}

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
    Packet tcp4, udp4, icmp4;
    Packet tcp6, udp6, icmp6;

    tcp4.init(this->packet_size);
    tcp4.init_ip4();
    tcp4.init_tcp4();
    tcp4.init_pf();

    udp4.init(this->packet_size);
    udp4.init_ip4();
    udp4.init_udp4();
    udp4.init_pf();

    icmp4.init(this->packet_size);
    icmp4.init_ip4();
    icmp4.init_icmp4();
    icmp4.init_pf();

    tcp6.init(this->packet_size);
    tcp6.init_ip6();
    tcp6.init_tcp6();
    tcp6.init_pf();

    udp6.init(this->packet_size);
    udp6.init_ip6();
    udp6.init_udp6();
    udp6.init_pf();

    icmp6.init(this->packet_size);
    icmp6.init_ip6();
    icmp6.init_icmp6();
    icmp6.init_pf();

    struct sockaddr_in dest_addr4;
    memset(&dest_addr4, 0, sizeof(dest_addr4));
    dest_addr4.sin_family = AF_INET;

    struct sockaddr_in6 dest_addr6;
    memset(&dest_addr6, 0, sizeof(dest_addr6));
    dest_addr6.sin6_family = AF_INET6;

    static const char ipv6_zeros[16] = {0};

    Ticker tick(this->interval);

    for (int port_idx = 0;; port_idx++) {
        if (port_idx >= this->ports_count) {
            port_idx = 0;
        }
        const int curr_src_port = this->src_port + port_idx;
        const int curr_dst_port = this->dst_port + port_idx;

        tick.sleep();
        const uint64_t index_timestamp_ms = to_ms(tick.timestamp);

        for (const auto &[_, path] : this->paths4) {
            if (path.src_addr == 0 || path.dst_addr == 0) {
                continue;
            }

            // sendto address.
            dest_addr4.sin_addr.s_addr = path.dst_addr;

            tcp4.ip4_addrs(path.src_addr, path.dst_addr);
            tcp4.tcp_ports(curr_src_port, curr_dst_port);
            tcp4.pf_names(index_timestamp_ms, path.src_name, path.dst_name);
            tcp4.checksum_tcp4();
            this->send4(tcp4, dest_addr4);

            udp4.ip4_addrs(path.src_addr, path.dst_addr);
            udp4.udp_ports(curr_src_port, curr_dst_port);
            udp4.pf_names(index_timestamp_ms, path.src_name, path.dst_name);
            udp4.checksum_udp4();
            this->send4(udp4, dest_addr4);

            icmp4.ip4_addrs(path.src_addr, path.dst_addr);
            icmp4.icmp4_sequence(curr_dst_port);
            icmp4.pf_names(index_timestamp_ms, path.src_name, path.dst_name);
            icmp4.checksum_icmp4();
            this->send4(icmp4, dest_addr4);
        }

        for (const auto &[_, path] : this->paths6) {
            if (memcmp(path.src_addr, ipv6_zeros, 16) == 0 || memcmp(path.dst_addr, ipv6_zeros, 16) == 0) {
                continue;
            }

            // sendto address.
            memcpy(&dest_addr6.sin6_addr, path.dst_addr, 16);

            tcp6.ip6_addrs(path.src_addr, path.dst_addr);
            tcp6.tcp_ports(curr_src_port, curr_dst_port);
            tcp6.pf_names(index_timestamp_ms, path.src_name, path.dst_name);
            tcp6.checksum_tcp6();
            this->send6(tcp6, dest_addr6);

            udp6.ip6_addrs(path.src_addr, path.dst_addr);
            udp6.udp_ports(curr_src_port, curr_dst_port);
            udp6.pf_names(index_timestamp_ms, path.src_name, path.dst_name);
            udp6.checksum_udp6();
            this->send6(udp6, dest_addr6);

            icmp6.ip6_addrs(path.src_addr, path.dst_addr);
            icmp6.icmp6_sequence(curr_dst_port);
            icmp6.pf_names(index_timestamp_ms, path.src_name, path.dst_name);
            icmp6.checksum_icmp6();
            this->send6(icmp6, dest_addr6);
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

void Sender::send4(Packet &p, sockaddr_in &addr) {
    if (sendto(this->sock4, p.vector.data(), p.size, 0, (sockaddr *)&addr, sizeof(addr)) < 0) {
        throw std::system_error(errno, std::system_category(), "sendto(IPv4) failed");
    }
}

void Sender::send6(Packet &p, sockaddr_in6 &addr) {
    if (sendto(this->sock6, p.vector.data(), p.size, 0, (sockaddr *)&addr, sizeof(addr)) < 0) {
        throw std::system_error(errno, std::system_category(), "sendto(IPv6) failed");
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
