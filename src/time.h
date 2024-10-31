#ifndef TICKER_H
#define TICKER_H

#include <time.h>

#include <chrono>
#include <cstdint>
#include <system_error>
#include <thread>

std::chrono::nanoseconds get_clock(int clock_id);
std::chrono::nanoseconds get_realtime_clock();
std::chrono::nanoseconds get_monotime_clock();

class Ticker {
public:
    std::chrono::nanoseconds timestamp;
    std::chrono::nanoseconds interval;
    std::chrono::nanoseconds max_interval;

    Ticker(std::chrono::nanoseconds interval);
    void reset();
    void reset(std::chrono::nanoseconds now);
    void sleep();
};

#endif
