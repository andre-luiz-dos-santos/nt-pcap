#ifndef SECRET_H
#define SECRET_H

#include <openssl/md5.h>

#include <string>

#include "packet.h"

class Secret {
public:
    std::string secret;

    void hash(void *dst, const void *src, size_t len);

    void sign(PacketFormat *pf);
    bool verify(PacketFormat *pf);
};

#endif
