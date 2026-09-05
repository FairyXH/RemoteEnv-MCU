#include "DeviceList.h"

#include <string.h>

namespace {
void copyField(char *dest, size_t capacity, const char *src) {
    if (!src) src = "";
    strncpy(dest, src, capacity - 1);
    dest[capacity - 1] = 0;
}
}  // namespace

void DeviceList::reset() {
    _count = 0;
    memset(_items, 0, sizeof(_items));
}

bool DeviceList::find(const char *deviceId, uint8_t &index) const {
    for (uint8_t i = 0; i < _count; ++i) {
        if (strcmp(_items[i].deviceId, deviceId) == 0) {
            index = i;
            return true;
        }
    }
    return false;
}

void DeviceList::upsert(const char *deviceId, const char *name, bool online) {
    if (!deviceId || !deviceId[0]) return;
    uint8_t index = 0;
    if (find(deviceId, index)) {
        copyField(_items[index].name, sizeof(_items[index].name), name);
        _items[index].online = online;
        _items[index].lastSeen = millis();
        return;
    }
    if (_count >= kMax) return;
    RemoteDevice &slot = _items[_count];
    memset(&slot, 0, sizeof(slot));
    copyField(slot.deviceId, sizeof(slot.deviceId), deviceId);
    copyField(slot.name, sizeof(slot.name), name ? name : deviceId);
    slot.online = online;
    slot.lastSeen = millis();
    _count++;
}

void DeviceList::sortOnlineFirst() {
    for (uint8_t i = 1; i < _count; ++i) {
        RemoteDevice cur = _items[i];
        int8_t pos = static_cast<int8_t>(i) - 1;
        while (pos >= 0 && cur.online && !_items[pos].online) {
            _items[pos + 1] = _items[pos];
            --pos;
        }
        _items[pos + 1] = cur;
    }
}

void DeviceList::touchWifi(const char *deviceId, uint8_t count) {
    uint8_t index = 0;
    if (!find(deviceId, index)) return;
    _items[index].wifiCount = count;
    _items[index].lastSeen = millis();
}

void DeviceList::touchBle(const char *deviceId, uint8_t count) {
    uint8_t index = 0;
    if (!find(deviceId, index)) return;
    _items[index].bleCount = count;
    _items[index].lastSeen = millis();
}