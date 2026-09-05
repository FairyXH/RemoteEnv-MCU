#pragma once

#include <Arduino.h>
#include <stdint.h>

// Pulls the latest data snapshot from the server every `intervalMs` ms and
// keeps a per-device cache. Falls back to fetching the full /api/latest-data
// envelope when the WebSocket subscription has not delivered a fresh frame
// inside the deadline. The first frame after a manual source switch uses
// refresh to bypass cached replays.
class PullScheduler {
public:
    void begin(const char *baseUrl, const char *token, uint32_t intervalMs = 5000);
    void stop();
    void loop();

    bool pullDue() const { return millis() >= _nextPullAt; }
    void markPulled() { _nextPullAt = millis() + _intervalMs; }
    uint32_t interval() const { return _intervalMs; }
    void setInterval(uint32_t intervalMs) { _intervalMs = intervalMs; }

private:
    char _baseUrl[128]{};
    char _token[128]{};
    uint32_t _intervalMs = 5000;
    uint32_t _nextPullAt = 0;
};