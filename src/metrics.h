#ifndef METRICS_H
#define METRICS_H

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#include "zstd.h"

class Metrics {
    std::mutex mutex;
    std::vector<char> buf;
    std::vector<char> buf_other;
    std::vector<char> compressed;
    int buf_used;
    int file_count;
    uint64_t lost_metrics;

    Zstd zstd;

    std::string tmp_file() { return this->queue_dir + "/.tmp"; };
    std::string new_file() { return this->queue_dir + "/metrics." + std::to_string(this->file_count++); };

public:
    std::string queue_dir;
    int max_queue_file_size;
    int rotate_after_size;
    int max_file_count;

    Metrics();

    void open();
    void rotate();
    void printf(const char *fmt, ...);

    void add_sent_point(int64_t sent_time, const char *ip_version, const char *src_name, const char *dst_name, int dst_port);
    void add_received_point(int64_t sent_time, int64_t received_time, const char *ip_version, const char *ip_protocol, const char *src_name, const char *dst_name, const char *src_ip, int dst_port, int ip_ttl);
};

#endif
