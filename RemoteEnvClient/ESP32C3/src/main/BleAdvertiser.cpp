#include "BleAdvertiser.h"

#include <NimBLEDevice.h>
#include <NimBLEUtils.h>
#include <string.h>

namespace {

// Helper that appends a single advertising-data (length, type, bytes) record.
bool appendRecord(uint8_t *dst, size_t &length, size_t capacity, uint8_t type, const uint8_t *data, size_t size) {
    if (size == 0 || size > 254) return false;
    if (length + 2 + size > capacity) return false;
    dst[length++] = static_cast<uint8_t>(size + 1);
    dst[length++] = type;
    memcpy(dst + length, data, size);
    length += size;
    return true;
}

// NimBLE advertiser singleton configured for the legacy broadcaster role.
NimBLEAdvertising *adv() {
    return NimBLEDevice::getAdvertising();
}

}  // namespace

void BleAdvertiser::begin() {
    stop();
}

void BleAdvertiser::stop() {
    if (_running) {
        NimBLEDevice::stopAdvertising();
    }
    _running = false;
    _count = 0;
    _index = 0;
}

void BleAdvertiser::setDevices(const BleBeaconDevice *devices, uint8_t count) {
    stop();
    for (uint8_t i = 0; i < count && i < kMaxDevices; ++i) {
        _devices[_count++] = devices[i];
    }
    if (_count == 0) return;
    // Non-connectable, scannable advertisement so iOS/Android scanners see
    // the broadcast without attempting a connection.
    NimBLEAdvertisementData scan;
    scan.setFlags(0x06);  // general discoverable + BR/EDR not supported
    adv()->setScanResponseData(scan);
    _nextAt = millis();
    _running = true;
}

void BleAdvertiser::loop() {
    if (!_running || _count == 0) return;
    const uint32_t now = millis();
    if (static_cast<int32_t>(now - _nextAt) >= 0) {
        _nextAt = now + kAdvertiseIntervalMs;
        const BleBeaconDevice &dev = _devices[_index];

        NimBLEAdvertisementData data;
        uint8_t raw[128]{};
        size_t rawLength = 0;
        if (dev.name[0]) {
            // Short name AD record (0x08) so legacy scanners pick it up.
            data.setName(dev.name);
            appendRecord(raw, rawLength, sizeof(raw), 0x08,
                         reinterpret_cast<const uint8_t *>(dev.name),
                         strlen(dev.name));
        }
        if (dev.manufacturerSize > 0) {
            uint8_t payload[66]{};
            // Little-endian manufacturer ID, then manufacturer data.
            payload[0] = static_cast<uint8_t>(dev.manufacturerId & 0xff);
            payload[1] = static_cast<uint8_t>((dev.manufacturerId >> 8) & 0xff);
            const size_t copySize = min<size_t>(dev.manufacturerSize, sizeof(dev.manufacturerData));
            memcpy(payload + 2, dev.manufacturerData, copySize);
            data.setManufacturerData(payload, copySize + 2);
            // 0xff = manufacturer specific AD record
            appendRecord(raw, rawLength, sizeof(raw), 0xff, payload, copySize + 2);
        }
        if (dev.serviceCount > 0) {
            std::vector<NimBLEUUID> list;
            list.reserve(dev.serviceCount);
            for (uint8_t i = 0; i < dev.serviceCount; ++i) {
                list.emplace_back(dev.serviceUuids[i]);
                if (list.size() >= 8) break;
            }
            data.setCompleteServices16(list);
            // 0x03 = complete list of 16-bit service UUIDs
            for (const auto &u : list) {
                if (u.bitSize() != BLE_UUID_TYPE_16) continue;
                uint8_t uuidBytes[2];
                const uint8_t *value = u.getValue();
                if (!value) continue;
                memcpy(uuidBytes, value, sizeof(uuidBytes));
                appendRecord(raw, rawLength, sizeof(raw), 0x03, uuidBytes, 2);
            }
        }
        if (dev.payloadSize > 0) {
            // Append the source's raw advertisement bytes so any vendor AD
            // records that were not parsed (iBeacon, Eddystone, etc.) are
            // preserved exactly as the source collector observed them.
            const size_t copySize = min<size_t>(dev.payloadSize, sizeof(dev.raw));
            appendRecord(raw, rawLength, sizeof(raw), 0xff,
                         reinterpret_cast<const uint8_t *>(dev.raw), copySize);
            // BleAdvertise/legacy AD only allows 31 bytes; keep raw payload
            // separate so we still expose it on the management page.
        }
        if (rawLength > 0) {
            data.addData(raw, rawLength);
        }
        adv()->setAdvertisementData(data);
        NimBLEDevice::startAdvertising(0);

        _index = static_cast<uint8_t>((_index + 1) % _count);
    }
}