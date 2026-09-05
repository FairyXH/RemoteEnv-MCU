#include "PullScheduler.h"

#include <Arduino.h>

void PullScheduler::begin(const char *baseUrl, const char *token, uint32_t intervalMs) {
    strncpy(_baseUrl, baseUrl ? baseUrl : "", sizeof(_baseUrl) - 1);
    _baseUrl[sizeof(_baseUrl) - 1] = 0;
    strncpy(_token, token ? token : "", sizeof(_token) - 1);
    _token[sizeof(_token) - 1] = 0;
    _intervalMs = intervalMs ? intervalMs : 5000;
    _nextPullAt = millis() + _intervalMs;
}

void PullScheduler::stop() {
    _baseUrl[0] = 0;
    _token[0] = 0;
    _nextPullAt = 0;
}

void PullScheduler::loop() {
    // All actual HTTP work is triggered from main.ino so this object is a
    // pure timer; keep the loop implementation for forward compatibility.
}