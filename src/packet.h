#ifndef PACKET_H
#define PACKET_H

#include <openssl/md5.h>

#include <cstdint>

const int MAX_NAME_SIZE = 7;

struct PacketFormat {
    char magic[4];
    int64_t index_timestamp_ms;
    int64_t sent_timestamp_ms;
    char src_name[MAX_NAME_SIZE + 1];
    char dst_name[MAX_NAME_SIZE + 1];

    // Has to be the last field in the struct for Secret::sign to work.
    char hash[MD5_DIGEST_LENGTH];
};

#endif
