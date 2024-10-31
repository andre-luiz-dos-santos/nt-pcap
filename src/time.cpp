#include "time.h"

#include <netdb.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <chrono>
#include <iostream>
#include <system_error>
#include <thread>

std::chrono::nanoseconds get_clock(int clock_id) {
    struct timespec t;

    int ret = clock_gettime(clock_id, &t);
    if (ret < 0) {
        throw std::system_error(errno, std::system_category(), "clock_gettime failed");
    }

    return std::chrono::seconds(t.tv_sec) + std::chrono::nanoseconds(t.tv_nsec);
}

std::chrono::nanoseconds get_realtime_clock() {
    return get_clock(CLOCK_REALTIME);
}

std::chrono::nanoseconds get_monotime_clock() {
    return get_clock(CLOCK_MONOTONIC);
}

Ticker::Ticker(std::chrono::nanoseconds interval)
    : interval(interval) {
    this->max_interval = interval * 2;
    this->reset();
}

void Ticker::reset() {
    this->reset(get_realtime_clock());
}

void Ticker::reset(std::chrono::nanoseconds now) {
    this->timestamp = now - (now % this->interval);
}

void Ticker::sleep() {
    // Calculate time before the next tick.
    this->timestamp += this->interval;
    auto now = get_realtime_clock();
    auto diff = this->timestamp - now;

    // If interval has already elapsed, reset and return.
    if (diff < std::chrono::nanoseconds(0)) {
        std::cout << "Ticker::sleep: diff < 0: " << diff.count() << std::endl;
        this->reset(now);
        return;  // no sleep needed
    }

    // If the clock has moved back by more than max_interval, reset.
    if (diff >= this->max_interval) {
        std::cout << "Ticker::sleep: diff >= max_interval: " << diff.count() << std::endl;
        this->reset(now + this->interval);
        diff = this->timestamp - now;  // reset changed this->timestamp
    }

    // Sleep for the remaining time.
    std::this_thread::sleep_for(diff);
}
