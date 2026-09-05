#include "BleAdvertiser.h"

#include <NimBLEDevice.h>
#include <NimBLEUtils.h>
#include <string.h>

namespace {

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
    // 25 ms in the BLE controller's 0.625 ms interval units.
    adv()->setMinInterval(40);
    adv()->setMaxInterval(40);
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
        if (dev.payloadSize > 0) {
            // A legacy advertising payload is at most 31 bytes. The captured
            // raw AD stream is already encoded, so replay it without wrapping
            // it in an extra manufacturer record.
            data.addData(dev.raw, min<size_t>(dev.payloadSize, 31));
        } else {
            data.setFlags(0x06);
            if (dev.name[0]) {
                std::string shortName(dev.name);
                if (shortName.length() > 12) shortName.resize(12);
                data.setName(shortName);
            }
        }
        if (dev.payloadSize == 0 && dev.manufacturerSize > 0) {
            uint8_t payload[66]{};
            // Little-endian manufacturer ID, then manufacturer data.
            payload[0] = static_cast<uint8_t>(dev.manufacturerId & 0xff);
            payload[1] = static_cast<uint8_t>((dev.manufacturerId >> 8) & 0xff);
            const size_t copySize = min<size_t>(dev.manufacturerSize, 10);
            memcpy(payload + 2, dev.manufacturerData, copySize);
            data.setManufacturerData(payload, copySize + 2);
        }
        NimBLEDevice::stopAdvertising();
        if (adv()->setAdvertisementData(data)) {
            NimBLEDevice::startAdvertising(0);
        }

        _index = static_cast<uint8_t>((_index + 1) % _count);
    }
}
