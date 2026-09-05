#pragma once

#include <Arduino.h>
#include <stdint.h>

// Replicated BLE device received from a remote Collector. The `payload`
// holds the source BLE advertisement section bytes (raw AD bytes captured
// by the Collector, after the PDU header) so the client can faithfully
// replay unknown vendor data instead of dropping fields the parser does
// not understand. Captured parsed fields are kept so it can also emit
// well-formed AD records before the raw blob for clients that respect
// the standard structure.
struct BleBeaconDevice {
    char address[20];
    char name[33];
    int8_t rssi;
    int8_t txPower;
    uint16_t manufacturerId;
    uint16_t serviceCount;
    uint16_t manufacturerSize;
    uint16_t payloadSize;
    char serviceUuids[16][40];
    uint8_t manufacturerData[64];
    uint8_t serviceData[64];
    // Raw advertisement bytes captured by the source collector, used to
    // ensure we forward every vendor-specific or unknown AD record.
    uint8_t raw[128];
};

// Cycles through multiple replicated BLE advertisements. NimBLE's legacy
// advertising accepts at most one payload at a time so we rebuild the
// advertisement before each broadcast. The full raw payload is replayed
// inside the standard AD stream so receivers see vendor data intact.
class BleAdvertiser {
public:
    void begin();
    void stop();
    void setDevices(const BleBeaconDevice* devices, uint8_t count);
    void loop();

    bool running() const { return _running; }
    uint8_t deviceCount() const { return _count; }
    const char* currentName() const { return _count ? _devices[_index].name : ""; }
    uint8_t currentRawLength() const { return _count ? _devices[_index].payloadSize : 0; }

private:
    static constexpr uint8_t kMaxDevices = 16;
    static constexpr uint32_t kAdvertiseIntervalMs = 25;

    BleBeaconDevice _devices[kMaxDevices]{};
    uint8_t _count = 0;
    uint8_t _index = 0;
    uint32_t _nextAt = 0;
    bool _running = false;
};
