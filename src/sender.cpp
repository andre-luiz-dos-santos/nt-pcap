#include "sender.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <iostream>

#include "checksum.h"
#include "metrics.h"
#include "net.h"
#include "packet.h"
#include "time.h"

extern Metrics metrics;

constexpr uint64_t to_ms(std::chrono::nanoseconds ns) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(ns).count();
}

std::array<char, MAX_NAME_SIZE> build_dst_key(const char name[MAX_NAME_SIZE]) {
    std::array<char, MAX_NAME_SIZE> key;
    memcpy(key.data(), name, MAX_NAME_SIZE);
    return key;
}

std::array<char, MAX_NAME_SIZE * 2> build_src_dst_key(const char src_name[MAX_NAME_SIZE], const char dst_name[MAX_NAME_SIZE]) {
    std::array<char, MAX_NAME_SIZE * 2> key;
    memcpy(key.data(), src_name, MAX_NAME_SIZE);
    memcpy(key.data() + MAX_NAME_SIZE, dst_name, MAX_NAME_SIZE);
    return key;
}

void Sender::index() {
    for (auto &path : this->paths4_vec) {
        auto key = build_src_dst_key(path.src_name, path.dst_name);
        auto [_, ok] = this->paths4_map.try_emplace(key, &path);
        if (ok == false) {
            throw std::runtime_error("Path from " + std::string(path.src_name) + " to " + std::string(path.dst_name) + " already exists in paths4");
        }
        if (path.dst_ip_dyn == true) {
            auto dst_key = build_dst_key(path.dst_name);
            this->dyn_dst_paths4[dst_key].push_back(&path);
        }
    }
    for (auto &path : this->paths6_vec) {
        auto key = build_src_dst_key(path.src_name, path.dst_name);
        auto [_, ok] = this->paths6_map.try_emplace(key, &path);
        if (ok == false) {
            throw std::runtime_error("Path from " + std::string(path.src_name) + " to " + std::string(path.dst_name) + " already exists in paths6");
        }
        if (path.dst_ip_dyn == true) {
            auto dst_key = build_dst_key(path.dst_name);
            this->dyn_dst_paths6[dst_key].push_back(&path);
        }
    }
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

    sockaddr_in dest_addr4;
    memset(&dest_addr4, 0, sizeof(dest_addr4));
    dest_addr4.sin_family = AF_INET;

    sockaddr_in6 dest_addr6;
    memset(&dest_addr6, 0, sizeof(dest_addr6));
    dest_addr6.sin6_family = AF_INET6;

    std::vector<Path4> paths4(this->paths4_vec.size());
    std::vector<Path6> paths6(this->paths6_vec.size());

    size_t other4_idx = 0;
    size_t other6_idx = 0;
    Path4 other_path4;
    Path6 other_path6;
    memset(&other_path4, 0, sizeof(other_path4));
    memset(&other_path6, 0, sizeof(other_path6));

    Ticker tick(this->interval);

    for (int port_idx = 0;; port_idx++) {
        if (port_idx >= this->ports_count) {
            port_idx = 0;
        }
        const int curr_src_port = this->src_port + port_idx;
        const int curr_dst_port = this->dst_port + port_idx;

        {  // Copy to avoid mutex.lock() during the sending loop.
            std::lock_guard<std::mutex> guard(this->mtx);
            static_assert(std::is_trivially_copyable<Path4>::value);
            static_assert(std::is_trivially_copyable<Path6>::value);
            memcpy(paths4.data(), this->paths4_vec.data(), this->paths4_vec.size() * sizeof(Path4));
            memcpy(paths6.data(), this->paths6_vec.data(), this->paths6_vec.size() * sizeof(Path6));
        }

        if (paths4.empty() == false) {
            if (other4_idx >= paths4.size()) other4_idx = 0;
            other_path4 = paths4[other4_idx++];
        }
        if (paths6.empty() == false) {
            if (other6_idx >= paths6.size()) other6_idx = 0;
            other_path6 = paths6[other6_idx++];
        }

        tick.sleep();
        const uint64_t index_timestamp_ms = to_ms(tick.timestamp);

        for (const auto &path : paths4) {
            if (path.src_ip4 == 0 || path.dst_ip4 == 0) {
                continue;
            }

            // sendto address.
            dest_addr4.sin_addr.s_addr = path.dst_ip4;

            tcp4.ip4_addrs(path.src_ip4, path.dst_ip4);
            tcp4.tcp_ports(curr_src_port, curr_dst_port);
            tcp4.pf_names(index_timestamp_ms, path.src_name, path.dst_name);
            tcp4.pf_other4(other_path4.src_name, other_path4.dst_name, other_path4.dst_ip4, other_path4.index_timestamp_ms);
            tcp4.checksum_tcp4();
            this->send4(tcp4, dest_addr4);

            udp4.ip4_addrs(path.src_ip4, path.dst_ip4);
            udp4.udp_ports(curr_src_port, curr_dst_port);
            udp4.pf_names(index_timestamp_ms, path.src_name, path.dst_name);
            udp4.pf_other4(other_path4.src_name, other_path4.dst_name, other_path4.dst_ip4, other_path4.index_timestamp_ms);
            udp4.checksum_udp4();
            this->send4(udp4, dest_addr4);

            icmp4.ip4_addrs(path.src_ip4, path.dst_ip4);
            icmp4.icmp4_sequence(curr_dst_port);
            icmp4.pf_names(index_timestamp_ms, path.src_name, path.dst_name);
            icmp4.pf_other4(other_path4.src_name, other_path4.dst_name, other_path4.dst_ip4, other_path4.index_timestamp_ms);
            icmp4.checksum_icmp4();
            this->send4(icmp4, dest_addr4);
        }

        for (const auto &path : paths6) {
            if (memcmp(path.src_ip6, ipv6_zeros, 16) == 0 || memcmp(path.dst_ip6, ipv6_zeros, 16) == 0) {
                continue;
            }

            // sendto address.
            memcpy(&dest_addr6.sin6_addr, path.dst_ip6, 16);

            tcp6.ip6_addrs(path.src_ip6, path.dst_ip6);
            tcp6.tcp_ports(curr_src_port, curr_dst_port);
            tcp6.pf_names(index_timestamp_ms, path.src_name, path.dst_name);
            tcp6.pf_other6(other_path6.src_name, other_path6.dst_name, other_path6.dst_ip6, other_path6.index_timestamp_ms);
            tcp6.checksum_tcp6();
            this->send6(tcp6, dest_addr6);

            udp6.ip6_addrs(path.src_ip6, path.dst_ip6);
            udp6.udp_ports(curr_src_port, curr_dst_port);
            udp6.pf_names(index_timestamp_ms, path.src_name, path.dst_name);
            udp6.pf_other6(other_path6.src_name, other_path6.dst_name, other_path6.dst_ip6, other_path6.index_timestamp_ms);
            udp6.checksum_udp6();
            this->send6(udp6, dest_addr6);

            icmp6.ip6_addrs(path.src_ip6, path.dst_ip6);
            icmp6.icmp6_sequence(curr_dst_port);
            icmp6.pf_names(index_timestamp_ms, path.src_name, path.dst_name);
            icmp6.pf_other6(other_path6.src_name, other_path6.dst_name, other_path6.dst_ip6, other_path6.index_timestamp_ms);
            icmp6.checksum_icmp6();
            this->send6(icmp6, dest_addr6);
        }

        // Add metrics outside the loop that sends packets.
        for (const auto &path : paths4) {
            if (path.src_ip4 == 0 || path.dst_ip4 == 0) {
                continue;
            }
            metrics.add_sent_point(
                index_timestamp_ms,
                "IP4",
                path.src_name,
                path.dst_name,
                curr_dst_port);
        }
        for (const auto &path : paths6) {
            if (memcmp(path.src_ip6, ipv6_zeros, 16) == 0 || memcmp(path.dst_ip6, ipv6_zeros, 16) == 0) {
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

/**
 * Set dst_ip4 for path src_name -> dst_name.
 * Returns true if the path was found, false otherwise.
 */
bool Sender::set_dst_ip4(const char src_name[MAX_NAME_SIZE], const char dst_name[MAX_NAME_SIZE], uint32_t ip4, uint64_t index_timestamp_ms) {
    auto key = build_src_dst_key(src_name, dst_name);
    auto it = this->paths4_map.find(key);
    if (it == this->paths4_map.end()) {
        return false;  // Path not found
    }
    auto path = it->second;
    if (path->dst_ip_dyn == false) {
        return true;  // Found static path
    }

    std::lock_guard<std::mutex> guard(this->mtx);

    path->index_timestamp_ms = index_timestamp_ms;

    if (path->dst_ip4 == ip4) {
        return true;  // Found same-address path
    }

    path->dst_ip4 = ip4;
    std::cout << "Destination for path " << src_name << " -> " << dst_name
              << " updated to " << ip_to_str(ip4) << std::endl;

    return true;
}

/**
 * Set dst_ip6 for path src_name -> dst_name.
 * Returns true if the path was found, false otherwise.
 */
bool Sender::set_dst_ip6(const char src_name[MAX_NAME_SIZE], const char dst_name[MAX_NAME_SIZE], const uint8_t ip6[16], uint64_t index_timestamp_ms) {
    auto key = build_src_dst_key(src_name, dst_name);
    auto it = this->paths6_map.find(key);
    if (it == this->paths6_map.end()) {
        return false;  // Path not found
    }
    auto path = it->second;
    if (path->dst_ip_dyn == false) {
        return true;  // Found static path
    }

    std::lock_guard<std::mutex> guard(this->mtx);

    path->index_timestamp_ms = index_timestamp_ms;

    if (memcmp(path->dst_ip6, ip6, 16) == 0) {
        return true;  // Found same-address path
    }

    memcpy(path->dst_ip6, ip6, 16);
    std::cout << "Destination for path " << src_name << " -> " << dst_name
              << " updated to " << ip_to_str(ip6) << std::endl;

    return true;
}

/**
 * Set dst_ip4 for paths matching * -> dst_name.
 */
void Sender::set_dyn_dst_ip4(const char src_name[MAX_NAME_SIZE], const char dst_name[MAX_NAME_SIZE], uint32_t ip4, uint64_t index_timestamp_ms) {
    if (index_timestamp_ms == 0) {
        return;  // Not dynamic on sender (src_name).
    }

    auto dst_key = build_dst_key(dst_name);
    auto it = this->dyn_dst_paths4.find(dst_key);
    if (it == this->dyn_dst_paths4.end()) {
        return;  // No dynamic paths to dst_name.
    }
    auto &paths = it->second;
    assert(paths.empty() == false);

    std::lock_guard<std::mutex> guard(this->mtx);

    for (auto path : paths) {
        assert(path->dst_ip_dyn == true);

        if (path->dst_ip4 == ip4) {
            continue;
        } else if (path->index_timestamp_ms >= index_timestamp_ms) {
            continue;
        }

        path->dst_ip4 = ip4;
        path->index_timestamp_ms = index_timestamp_ms;
        std::cout << "Destination for path " << path->src_name << " -> " << path->dst_name
                  << " updated to " << ip_to_str(ip4)
                  << " (from " << src_name << ")" << std::endl;
    }
}

/**
 * Set dst_ip6 for paths matching * -> dst_name.
 */
void Sender::set_dyn_dst_ip6(const char src_name[MAX_NAME_SIZE], const char dst_name[MAX_NAME_SIZE], const uint8_t ip6[16], uint64_t index_timestamp_ms) {
    if (index_timestamp_ms == 0) {
        return;  // Not dynamic on sender (src_name).
    }

    auto dst_key = build_dst_key(dst_name);
    auto it = this->dyn_dst_paths6.find(dst_key);
    if (it == this->dyn_dst_paths6.end()) {
        return;  // No dynamic paths to dst_name.
    }
    auto &paths = it->second;
    assert(paths.empty() == false);

    std::lock_guard<std::mutex> guard(this->mtx);

    for (auto path : paths) {
        assert(path->dst_ip_dyn == true);

        if (memcmp(path->dst_ip6, ip6, 16) == 0) {
            continue;
        } else if (path->index_timestamp_ms >= index_timestamp_ms) {
            continue;
        }

        memcpy(path->dst_ip6, ip6, 16);
        path->index_timestamp_ms = index_timestamp_ms;
        std::cout << "Destination for path " << path->src_name << " -> " << path->dst_name
                  << " updated to " << ip_to_str(ip6)
                  << " (from " << src_name << ")" << std::endl;
    }
}
