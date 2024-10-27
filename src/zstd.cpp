#include "zstd.h"

#include <stdexcept>

Zstd::Zstd() {
    ctx = ZSTD_createCCtx();
    if (!ctx) {
        throw std::runtime_error("ZSTD_createCCtx failed");
    }
}

Zstd::~Zstd() {
    ZSTD_freeCCtx(ctx);
}

size_t Zstd::dst_len_needed(size_t src_len) {
    return ZSTD_compressBound(src_len);
}

size_t Zstd::compress(void *dst, size_t dst_len, const void *src, size_t src_len) {
    int r = ZSTD_compressCCtx(this->ctx, dst, dst_len, src, src_len, 1);
    if (ZSTD_isError(r)) {
        throw std::runtime_error("ZSTD_compressCCtx failed");
    }
    return r;
}

std::vector<char> Zstd::compress(const void *src, size_t src_len) {
    std::vector<char> dst(ZSTD_compressBound(src_len));
    dst.resize(this->compress(dst.data(), dst.size(), src, src_len));
    return dst;
}

std::vector<char> Zstd::compress(const std::vector<char> &src) {
    return this->compress(src.data(), src.size());
}
