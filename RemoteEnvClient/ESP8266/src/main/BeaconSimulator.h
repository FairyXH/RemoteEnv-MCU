#pragma once

#include <Arduino.h>
#include <stdint.h>

struct BeaconNetwork {
    char ssid[33];
    uint8_t bssid[6];
    int8_t rssi;
    uint8_t channel;
    uint8_t encryption;
};

class BeaconSimulator {
public:
    void begin();
    void stop();
    void setNetworks(const BeaconNetwork* networks, uint8_t count);

    void loop();
    bool running() const { return _running; }
    uint8_t currentChannel() const { return _channel; }
    const char* currentSsid() const { return _count ? _networks[_index].ssid : ""; }

private:
    static constexpr uint32_t kBeaconIntervalMs = 25;

    static constexpr uint8_t kMaxNetworks = 24;
    BeaconNetwork _networks[kMaxNetworks]{};
    uint8_t _count = 0;
    uint8_t _index = 0;
    uint8_t _channel = 1;
    uint32_t _nextBeaconAt = 0;
    uint32_t _dwellStartedAt = 0;
    bool _running = false;


    void sendBeacon(const BeaconNetwork& network);

};