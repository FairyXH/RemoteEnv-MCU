#pragma once

#include <Arduino.h>
#include <stdint.h>

// WiFi Beacon network entry received from a remote Collector via the
// server. Only the SSID and BSSID are needed because the client always
// broadcasts on the management STA channel.
struct BeaconNetwork {
    char ssid[33];
    uint8_t bssid[6];
};

// Lightweight 802.11 beacon simulator built on esp_wifi_80211_tx().
// Locked to the management STA channel; do not call esp_wifi_set_channel()
// while the STA is connected or the management page disconnects.
class BeaconSimulator {
public:
    void begin();
    void stop();
    void setNetworks(const BeaconNetwork* networks, uint8_t count);
    void loop();

    bool running() const { return _running; }
    uint8_t currentChannel() const { return _channel; }
    const char* currentSsid() const { return _count ? _networks[_index].ssid : ""; }
    uint8_t networkCount() const { return _count; }

private:
    static constexpr uint32_t kBeaconIntervalMs = 25;
    static constexpr uint8_t kMaxNetworks = 24;

    BeaconNetwork _networks[kMaxNetworks]{};
    uint8_t _count = 0;
    uint8_t _index = 0;
    uint8_t _channel = 1;
    uint32_t _nextBeaconAt = 0;
    bool _running = false;

    void sendBeacon(const BeaconNetwork& network);
};