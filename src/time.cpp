#include "time.h"

#include <netdb.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <iostream>
#include <system_error>
#include <thread>

time_t get_clock(int clock_id) {
    struct timespec t;

    int ret = clock_gettime(clock_id, &t);
    if (ret < 0) {
        throw std::system_error(errno, std::system_category(), "clock_gettime failed");
    }

    return t.tv_sec * 1000000 + t.tv_nsec / 1000;
}

time_t get_realtime_clock() {
    return get_clock(CLOCK_REALTIME);
}

time_t get_monotime_clock() {
    return get_clock(CLOCK_MONOTONIC);
}

Ticker::Ticker(int interval)
    : interval(interval) {
    this->max_interval = interval * 2;
    this->reset();
}

void Ticker::reset() {
    this->reset(get_realtime_clock());
}

void Ticker::reset(time_t now) {
    this->timestamp = now - (now % this->interval);
}

void Ticker::sleep() {
    // Calculate microseconds before the next tick.
    this->timestamp += this->interval;
    auto now = get_realtime_clock();
    auto diff = this->timestamp - now;

    // If interval has already elapsed, reset and return.
    if (diff < 0) {
        std::cout << "Ticker::sleep: diff < 0: " << diff << std::endl;
        this->reset(now);
        return;  // no sleep needed
    }

    // If the clock has moved back by more than max_interval, reset.
    if (diff >= this->max_interval) {
        std::cout << "Ticker::sleep: diff >= max_interval: " << diff << std::endl;
        this->reset(now + this->interval);
        diff = this->timestamp - now;
    }

    // Sleep for the remaining time.
    std::this_thread::sleep_for(std::chrono::microseconds(diff));
}
