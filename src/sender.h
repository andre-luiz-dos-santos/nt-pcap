#ifndef SENDER_H
#define SENDER_H

#include <array>
#include <string>
#include <unordered_map>

#include "packet.h"

/**
 * Created by ChatGPT as the fastest way to hash an array of 16 bytes.
 */
struct ArrayHash {
    std::size_t operator()(const std::array<char, (MAX_NAME_SIZE + 1) * 2> &arr) const {
        const uint64_t *data = reinterpret_cast<const uint64_t *>(arr.data());
        return data[0] ^ data[1];
    }
};

struct Path4 {
    char src_name[MAX_NAME_SIZE + 1];
    char dst_name[MAX_NAME_SIZE + 1];

    uint32_t src_addr;
    uint32_t dst_addr;

    bool src_addr_dyn;
    bool dst_addr_dyn;
};

struct Path6 {
    char src_name[MAX_NAME_SIZE + 1];
    char dst_name[MAX_NAME_SIZE + 1];

    char src_addr[16];
    char dst_addr[16];

    bool src_addr_dyn;
    bool dst_addr_dyn;
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
    int interval_ms;
    std::unordered_map<std::array<char, (MAX_NAME_SIZE + 1) * 2>, Path4, ArrayHash> paths4;
    std::unordered_map<std::array<char, (MAX_NAME_SIZE + 1) * 2>, Path6, ArrayHash> paths6;

    void open();
    void loop();
    void add_path4(const char *src_name, const char *dst_name, Path4 &path);
    void add_path6(const char *src_name, const char *dst_name, Path6 &path);
    bool set_remote_ip4(const char *src_name, const char *dst_name, uint32_t addr);
    bool set_remote_ip6(const char *src_name, const char *dst_name, const void *addr);
};

#endif
