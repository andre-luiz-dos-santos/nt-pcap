#ifndef SENDER_H
#define SENDER_H

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <array>
#include <chrono>
#include <mutex>
#include <string>
#include <unordered_map>

#include "packet.h"

template <size_t N>
struct std::hash<std::array<char, N>> {
    static_assert(N == 8 || N == 16, "Unsupported array size");
    std::size_t operator()(const std::array<char, N> &arr) const {
        if constexpr (N == 16) {
            auto data = reinterpret_cast<const uint64_t *>(arr.data());
            return data[0] ^ data[1];
        } else if constexpr (N == 8) {
            auto data = reinterpret_cast<const uint32_t *>(arr.data());
            return data[0] ^ data[1];
        }
    }
};

struct Path4 {
    char src_name[MAX_NAME_SIZE];
    char dst_name[MAX_NAME_SIZE];

    uint32_t src_ip4;
    uint32_t dst_ip4;

    bool src_ip_dyn;
    bool dst_ip_dyn;

    uint64_t index_timestamp_ms;  // last received from dst_name
};

struct Path6 {
    char src_name[MAX_NAME_SIZE];
    char dst_name[MAX_NAME_SIZE];

    uint8_t src_ip6[16];
    uint8_t dst_ip6[16];

    bool src_ip_dyn;
    bool dst_ip_dyn;

    uint64_t index_timestamp_ms;  // last received from dst_name
};

class Sender {
private:
    int sock4;
    int sock6;

public:
    int src_port;
    int dst_port;
    int ports_count;
    int packet_size;
    std::chrono::nanoseconds interval;

    // Guards src_ip[46], dst_ip[46], index_timestamp_ms.
    std::mutex mtx;

    std::vector<Path4> paths4_vec;
    std::vector<Path6> paths6_vec;

    std::unordered_map<std::array<char, MAX_NAME_SIZE * 2>, Path4 *> paths4_map;
    std::unordered_map<std::array<char, MAX_NAME_SIZE * 2>, Path6 *> paths6_map;

    std::unordered_map<std::array<char, MAX_NAME_SIZE>, std::vector<Path4 *>> dyn_dst_paths4;
    std::unordered_map<std::array<char, MAX_NAME_SIZE>, std::vector<Path6 *>> dyn_dst_paths6;

    void index();
    void open();
    void loop();
    void send4(Packet &p, sockaddr_in &addr);
    void send6(Packet &p, sockaddr_in6 &addr);
    bool set_dst_ip4(const char src_name[MAX_NAME_SIZE], const char dst_name[MAX_NAME_SIZE], uint32_t ip4, uint64_t index_timestamp_ms);
    bool set_dst_ip6(const char src_name[MAX_NAME_SIZE], const char dst_name[MAX_NAME_SIZE], const uint8_t ip6[16], uint64_t index_timestamp_ms);
    void set_dyn_dst_ip4(const char src_name[MAX_NAME_SIZE], const char dst_name[MAX_NAME_SIZE], uint32_t ip4, uint64_t index_timestamp_ms);
    void set_dyn_dst_ip6(const char src_name[MAX_NAME_SIZE], const char dst_name[MAX_NAME_SIZE], const uint8_t ip6[16], uint64_t index_timestamp_ms);
};

#endif
