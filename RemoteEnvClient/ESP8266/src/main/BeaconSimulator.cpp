#include "BeaconSimulator.h"

#include <ESP8266WiFi.h>
#include "user_interface.h"

namespace {
constexpr uint8_t kFrameControlBeacon = 0x80;
constexpr uint8_t kBroadcastAddress[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

void appendIe(uint8_t* frame, uint16_t& length, uint8_t id, const uint8_t* data, uint8_t size) {
    frame[length++] = id;
    frame[length++] = size;
    memcpy(frame + length, data, size);
    length += size;
}

}  // namespace

void BeaconSimulator::begin() {
    stop();
}

void BeaconSimulator::stop() {
    _running = false;
    _count = 0;
    _index = 0;

}


void BeaconSimulator::setNetworks(const BeaconNetwork* networks, uint8_t count) {
    stop();
    for (uint8_t i = 0; i < count && i < kMaxNetworks; ++i) {
        if (networks[i].ssid[0] == '\0') continue;
        _networks[_count++] = networks[i];
    }
    if (_count == 0) return;
    _channel = WiFi.status() == WL_CONNECTED ? WiFi.channel() : _networks[0].channel;
    if (WiFi.status() != WL_CONNECTED) wifi_set_channel(_channel);
    _nextBeaconAt = millis();
    _running = true;
}

void BeaconSimulator::loop() {
    if (!_running || _count == 0) return;
    const uint32_t now = millis();

    if (static_cast<int32_t>(now - _nextBeaconAt) < 0) return;
    _nextBeaconAt = now + kBeaconIntervalMs;
    sendBeacon(_networks[_index]);
    _index = static_cast<uint8_t>((_index + 1) % _count);
}

void BeaconSimulator::sendBeacon(const BeaconNetwork& network) {
    uint8_t frame[256]{};
    uint16_t length = 0;
    frame[length++] = kFrameControlBeacon;
    frame[length++] = 0x00;
    frame[length++] = 0x00;
    frame[length++] = 0x00;
    memcpy(frame + length, kBroadcastAddress, 6); length += 6;
    memcpy(frame + length, network.bssid, 6); length += 6;
    memcpy(frame + length, network.bssid, 6); length += 6;
    frame[length++] = 0x00;
    frame[length++] = 0x00;
    const uint64_t timestamp = static_cast<uint64_t>(micros());
    memcpy(frame + length, &timestamp, 8); length += 8;
    frame[length++] = 0x64; frame[length++] = 0x00;
    frame[length++] = network.encryption ? 0x31 : 0x21;
    frame[length++] = 0x04;
    appendIe(frame, length, 0, reinterpret_cast<const uint8_t*>(network.ssid), static_cast<uint8_t>(strlen(network.ssid)));
    const uint8_t rates[] = {0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
    appendIe(frame, length, 1, rates, sizeof(rates));
    const uint8_t dsParameter = WiFi.status() == WL_CONNECTED ? WiFi.channel() : network.channel;
    appendIe(frame, length, 3, &dsParameter, 1);
    const int result = wifi_send_pkt_freedom(frame, length, true);
    if (result != 0) Serial.printf("Beacon send failed: %d\n", result);
}