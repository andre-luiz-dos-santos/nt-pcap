#include "metrics.h"

#include <sys/mman.h>

#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <thread>
#include <utility>

namespace fs = std::filesystem;

Metrics::Metrics()
    : buf_used(0),
      file_count(0),
      lost_metrics(0),
      queue_dir("."),
      max_queue_file_size(2 * 1024 * 1024),
      rotate_after_size(1 * 1024 * 1024),
      max_file_count(10) {
    this->file_count = ::time(nullptr);
}

void Metrics::open() {
    this->buf.resize(this->max_queue_file_size);
    this->buf_other.resize(this->max_queue_file_size);
    this->compressed.resize(this->zstd.dst_len_needed(this->max_queue_file_size));

    if (::mlock(this->buf.data(), this->buf.size()) == -1) {
        ::perror("mlock");
    }
    if (::mlock(this->buf_other.data(), this->buf_other.size()) == -1) {
        ::perror("mlock");
    }
    if (::mlock(this->compressed.data(), this->compressed.size()) == -1) {
        ::perror("mlock");
    }

    std::regex pattern(R"(metrics\.(\d+))");
    for (const auto &entry : fs::directory_iterator(this->queue_dir)) {
        if (entry.is_regular_file()) {
            std::string filename = entry.path().filename().string();
            std::smatch match;

            if (filename == ".tmp") {
                // Will be overwritten.
            } else if (std::regex_match(filename, match, pattern)) {
                int n = std::stoi(match[1]);
                if (n > this->file_count) {
                    this->file_count = n + 1;
                }
            } else {
                throw std::runtime_error("Unexpected file name in queue directory: " + filename);
            }
        }
    }
}

void Metrics::rotate() {
    int cnt = 0;
    for (const auto &entry : fs::directory_iterator(this->queue_dir)) {
        if (entry.is_regular_file()) {
            ++cnt;
        }
    }
    if (cnt >= this->max_file_count) {
        return;
    }

    uint64_t lost_metrics;
    int buf_other_used;
    {
        std::lock_guard<std::mutex> lock(this->mutex);

        if (this->buf_used == 0) {
            return;
        } else if (cnt >= 1 && this->buf_used < this->rotate_after_size) {
            return;
        }

        this->buf_other.swap(this->buf);
        buf_other_used = std::exchange(this->buf_used, 0);

        lost_metrics = std::exchange(this->lost_metrics, 0);
    }

    // Only print when a rotation happens.
    if (lost_metrics > 0) {
        std::cout << "Lost " << lost_metrics << " metrics" << std::endl;
    }

    auto compressed_len = this->zstd.compress(
        this->compressed.data(), this->compressed.size(),
        buf_other.data(), buf_other_used);

    std::ofstream f;
    f.exceptions(std::ofstream::failbit | std::ofstream::badbit);
    f.open(this->tmp_file(), std::ios::out | std::ios::trunc);
    f.write(this->compressed.data(), compressed_len);
    f.close();

    std::filesystem::rename(this->tmp_file(), this->new_file());
}

void Metrics::printf(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    {
        std::lock_guard<std::mutex> lock(this->mutex);

        char *buf = this->buf.data() + this->buf_used;
        int len = this->buf.size() - this->buf_used;

        int written = ::vsnprintf(buf, len, fmt, args);
        if (written > 0 && written <= len) {
            this->buf_used += written;
        } else {
            this->lost_metrics++;
        }
    }

    va_end(args);
}

void Metrics::add_sent_point(int64_t sent_time, const char *ip_version, const char *src_name, const char *dst_name, int dst_port) {
    this->printf("s\t%ld\t%s\t%s\t%s\t%d\n", sent_time, ip_version, src_name, dst_name, dst_port);
}

void Metrics::add_received_point(int64_t sent_time, int64_t delay_ms, const char *ip_version, const char *ip_protocol, const char *src_name, const char *dst_name, const char *src_ip, int dst_port, int ip_ttl) {
    this->printf("r\t%ld\t%ld\t%s\t%s\t%s\t%s\t%s\t%d\t%d\n", sent_time, delay_ms, ip_version, ip_protocol, src_name, dst_name, src_ip, dst_port, ip_ttl);
}
