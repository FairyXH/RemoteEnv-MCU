#pragma once

#include <Arduino.h>
#include <stdint.h>

// Per-remote Collector entry. `online` is the live state from the
// server's `device_list`; `wifiCount`/`bleCount` are refreshed whenever an
// envelope is received for that source.
struct RemoteDevice {
    char deviceId[65];
    char name[65];
    bool online;
    uint8_t wifiCount;
    uint8_t bleCount;
    uint32_t lastSeen;  // millis() of last envelope or device_list update
};

class DeviceList {
public:
    void reset();
    void sortOnlineFirst();

    bool find(const char *deviceId, uint8_t &index) const;
    void upsert(const char *deviceId, const char *name, bool online);

    uint8_t count() const { return _count; }
    const RemoteDevice *at(uint8_t index) const { return index < _count ? &_items[index] : nullptr; }
    void touchWifi(const char *deviceId, uint8_t count);
    void touchBle(const char *deviceId, uint8_t count);

private:
    static constexpr uint8_t kMax = 48;
    RemoteDevice _items[kMax]{};
    uint8_t _count = 0;
};