#include "secret.h"

#include <cassert>
#include <cstring>

void Secret::hash(void *dst, const void *src, size_t len) {
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, this->secret.data(), this->secret.size());
    MD5_Update(&ctx, src, len);
    MD5_Final((unsigned char *)dst, &ctx);
}

void Secret::sign(PacketFormat *pf) {
    static_assert(sizeof(pf->hash) == MD5_DIGEST_LENGTH);
    this->hash(pf->hash, pf, sizeof(PacketFormat) - sizeof(pf->hash));
}

bool Secret::verify(PacketFormat *pf) {
    char buf[sizeof(pf->hash)];
    this->hash(buf, pf, sizeof(*pf) - sizeof(pf->hash));
    return ::memcmp(buf, pf->hash, sizeof(pf->hash)) == 0;
}
