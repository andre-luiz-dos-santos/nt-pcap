#ifndef TICKER_H
#define TICKER_H

#include <time.h>

#include <chrono>
#include <cstdint>
#include <system_error>
#include <thread>

// time_t is a clock's time in microseconds.
typedef int64_t time_t;

time_t get_clock(int clock_id);
time_t get_realtime_clock();
time_t get_monotime_clock();

class Ticker {
public:
    time_t timestamp;
    int interval;
    int max_interval;

    Ticker(int interval);
    void reset();
    void reset(time_t now);
    void sleep();
};

#endif
