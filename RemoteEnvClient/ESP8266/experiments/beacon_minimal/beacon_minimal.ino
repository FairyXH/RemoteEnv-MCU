#include <Arduino.h>
#include <ESP8266WiFi.h>
#include "user_interface.h"

namespace {
constexpr uint8_t kChannel = 1;
const uint8_t kBssid[6] = {0x02, 0x52, 0x45, 0x4d, 0x4f, 0x01};
const char kSsid[] = "RemoteTest";

void appendIe(uint8_t* frame, uint16_t& length, uint8_t id, const uint8_t* data, uint8_t size) {
    frame[length++] = id;
    frame[length++] = size;
    memcpy(frame + length, data, size);
    length += size;
}

void sendBeacon() {
    uint8_t frame[128]{};
    uint16_t length = 0;
    frame[length++] = 0x80;
    frame[length++] = 0x00;
    frame[length++] = 0x00;
    frame[length++] = 0x00;
    memset(frame + length, 0xff, 6); length += 6;
    memcpy(frame + length, kBssid, 6); length += 6;
    memcpy(frame + length, kBssid, 6); length += 6;
    frame[length++] = 0x00;
    frame[length++] = 0x00;
    const uint64_t timestamp = static_cast<uint64_t>(micros());
    memcpy(frame + length, &timestamp, sizeof(timestamp)); length += sizeof(timestamp);
    frame[length++] = 0x64;
    frame[length++] = 0x00;
    frame[length++] = 0x31;
    frame[length++] = 0x04;
    appendIe(frame, length, 0, reinterpret_cast<const uint8_t*>(kSsid), sizeof(kSsid) - 1);
    const uint8_t rates[] = {0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24};
    appendIe(frame, length, 1, rates, sizeof(rates));
    appendIe(frame, length, 3, &kChannel, 1);
    const int result = wifi_send_pkt_freedom(frame, length, true);
    if (result != 0) Serial.printf("send result=%d\n", result);
}
}

void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);
    wifi_set_channel(kChannel);
    Serial.println("Beacon minimal started");
}

void loop() {
    sendBeacon();
    delay(100);
}