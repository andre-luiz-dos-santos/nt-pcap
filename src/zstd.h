#ifndef ZSTD_H
#define ZSTD_H

#include <zstd.h>

#include <cstddef>
#include <vector>

class Zstd {
private:
    ZSTD_CCtx *ctx;

public:
    Zstd();
    ~Zstd();

    size_t compress(void *dst, size_t dst_len, const void *src, size_t src_len);
    size_t dst_len_needed(size_t src_len);
    std::vector<char> compress(const void *src, size_t src_len);
    std::vector<char> compress(const std::vector<char> &src);
};

#endif
