#include <Arduino.h>
#include <ArduinoJson.h>
#include <mbedtls/sha256.h>
#include <EEPROM.h>
#include <Preferences.h>
#include <WebServer.h>
#include <NimBLEDevice.h>
#include <WiFi.h>
#include <WebSocketsClient.h>
#include <sys/time.h>
#include <time.h>

namespace {
constexpr uint8_t kLedPin = 8;  // This board's onboard LED
constexpr uint8_t kConfigButtonPin = 0;  // GPIO0, active low
constexpr size_t kEepromSize = 4096;
constexpr uint32_t kConfigMagic = 0x52454334;
constexpr uint32_t kPreviousConfigMagic = 0x52454333;
constexpr uint32_t kOlderConfigMagic = 0x52454332;
constexpr uint8_t kMaxWifiNetworks = 5;
constexpr uint8_t kMaxServers = 3;
constexpr size_t kPasswordHashLength = 64;
constexpr size_t kSessionTokenLength = 32;
constexpr uint32_t kSessionTimeoutMs = 1800000;
constexpr uint32_t kUploadIntervalMs = 3000;
constexpr uint32_t kDefaultUploadIntervalSeconds = 15;
constexpr uint32_t kMinimumUploadIntervalSeconds = 10;
constexpr uint32_t kMaximumUploadIntervalSeconds = 30;
constexpr uint32_t kMinimumScanSliceMs = 5000;
constexpr size_t kWifiSnapshotBufferSize = 8192;
constexpr size_t kBluetoothSnapshotBufferSize = 12288;
constexpr char kBluetoothDataType[] = "bluetooth";
constexpr char kWifiDataType[] = "wifi";

constexpr uint32_t kWifiConnectTimeoutMs = 15000;
constexpr uint32_t kAuthTimeoutMs = 15000;
constexpr uint32_t kApplicationPingIntervalMs = 10000;
constexpr uint32_t kConfigModeTimeoutMs = 300000;
constexpr uint32_t kWifiRetryBaseIntervalMs = 5000;
constexpr uint32_t kWifiRetryMaximumIntervalMs = 60000;
constexpr uint32_t kWebSocketRetryIntervalMs = 5000;
constexpr uint8_t kLogCapacity = 20;
constexpr uint8_t kLogLineLength = 96;
constexpr time_t kMinimumValidEpoch = 1700000000;
constexpr char kApPassword[] = "12345678";

struct WifiConfig {
    char ssid[64];
    char password[64];
};

struct ServerConfig {
    char wsUrl[160];
    char token[160];
};

struct DeviceConfig {
    WifiConfig wifi[kMaxWifiNetworks];
    ServerConfig servers[kMaxServers];
    char deviceId[64];
    char passwordHash[65];
    uint32_t uploadIntervalSeconds;
};

struct StoredConfig {
    uint32_t magic;
    DeviceConfig config;
};

struct LegacyDeviceConfig {
    char wifiSsid[64];
    char wifiPassword[64];
    char wsUrl[160];
    char token[160];
    char deviceId[64];
    char passwordHash[65];
    uint32_t uploadIntervalSeconds;
};

struct LegacyStoredConfig {
    uint32_t magic;
    LegacyDeviceConfig config;
};

String getChipIdHex() {
    const uint64_t chipId = ESP.getEfuseMac();
    char value[17]{};
    snprintf(value, sizeof(value), "%04x%08x", static_cast<uint16_t>(chipId >> 32), static_cast<uint32_t>(chipId));
    return String(value);
}

DeviceConfig config;
WebSocketsClient websockets[kMaxServers];
WebServer webServer(80);
uint32_t nextUploadAt = 0;
uint32_t uploadIntervalSeconds = kDefaultUploadIntervalSeconds;
bool serverAuthenticated[kMaxServers]{};
bool configMode = false;
bool lastButtonState = HIGH;
uint32_t lastButtonChangeAt = 0;
char logLines[kLogCapacity][kLogLineLength];
uint8_t logCount = 0;
uint32_t configModeStartedAt = 0;
uint32_t lastConfigActivityAt = 0;
uint32_t wifiAttemptStartedAt = 0;
uint32_t nextWifiRetryAt = 0;
uint32_t wifiRetryDelayMs = kWifiRetryBaseIntervalMs;
uint8_t wifiIndex = 0;
uint8_t wifiRound = 0;
uint32_t nextWebSocketRetryAt[kMaxServers]{};
bool webServerStarted = false;
bool webRoutesRegistered = false;
bool wifiConnecting = false;
bool webSocketStarted[kMaxServers]{};
uint32_t connectedAt[kMaxServers]{};
uint32_t lastApplicationPingAt[kMaxServers]{};
char wifiSnapshot[kWifiSnapshotBufferSize] = "{\"networks\":[]}";
char bluetoothSnapshot[kBluetoothSnapshotBufferSize] = "{\"devices\":[]}";
size_t wifiSnapshotLength = sizeof("{\"networks\":[]}") - 1;
size_t bluetoothSnapshotLength = sizeof("{\"devices\":[]}") - 1;
uint64_t wifiSnapshotAt = 0;
uint64_t bluetoothSnapshotAt = 0;
bool wifiSnapshotReady = false;
bool bluetoothSnapshotReady = false;
SemaphoreHandle_t snapshotMutex = nullptr;
TaskHandle_t scanTaskHandle = nullptr;
bool scanTaskEnabled = false;
Preferences sequencePreferences;
uint64_t bluetoothSequence = 0;
uint64_t wifiSequence = 0;

void addLog(const String& message) {
    Serial.println(message);
    if (logCount < kLogCapacity) {
        message.substring(0, kLogLineLength - 1).toCharArray(logLines[logCount++], kLogLineLength);
        return;
    }
    for (uint8_t i = 1; i < kLogCapacity; ++i) {
        memcpy(logLines[i - 1], logLines[i], kLogLineLength);
    }
    message.substring(0, kLogLineLength - 1).toCharArray(logLines[kLogCapacity - 1], kLogLineLength);
}

bool hasAdminPassword() {
    return strlen(config.passwordHash) == kPasswordHashLength;
}

String passwordDigest(const String& password) {
    const String salted = String(getChipIdHex()) + ":" + password;
    uint8_t digest[32];
    mbedtls_sha256(reinterpret_cast<const unsigned char*>(salted.c_str()), salted.length(), digest, 0);
    String result;
    result.reserve(64);
    for (uint8_t byte : digest) {
        if (byte < 16) result += "0";
        result += String(byte, HEX);
    }
    return result;
}

bool constantTimeEquals(const char* left, const String& right) {
    if (strlen(left) != right.length()) {
        return false;
    }
    uint8_t difference = 0;
    for (size_t i = 0; i < right.length(); ++i) {
        difference |= static_cast<uint8_t>(left[i] ^ right[i]);
    }
    return difference == 0;
}

String sessionToken;
uint32_t sessionCreatedAt = 0;

void createSession() {
    char token[kSessionTokenLength + 1]{};
    for (uint8_t i = 0; i < kSessionTokenLength / 2; ++i) {
        const uint8_t value = static_cast<uint8_t>(esp_random());
        snprintf(token + i * 2, 3, "%02x", value);
    }
    sessionToken = token;
    sessionCreatedAt = millis();
}

bool sessionIsValid() {
    if (sessionToken.length() == 0 || millis() - sessionCreatedAt > kSessionTimeoutMs) {
        sessionToken = "";
        return false;
    }
    if (!webServer.hasHeader("Cookie")) {
        return false;
    }
    const String cookie = webServer.header("Cookie");
    const String expected = String("REMOTENV_SESSION=") + sessionToken;
    const int start = cookie.indexOf(expected);
    if (start < 0) return false;
    const int end = start + expected.length();
    return (start == 0 || cookie[start - 1] == ' ') &&
           (end == cookie.length() || cookie[end] == ';');
}

void sendSecurityHeaders() {
    webServer.sendHeader("Cache-Control", "no-store");
    webServer.sendHeader("Pragma", "no-cache");
    webServer.sendHeader("X-Content-Type-Options", "nosniff");
    webServer.sendHeader("X-Frame-Options", "DENY");
    webServer.sendHeader("Referrer-Policy", "no-referrer");
}

bool requireSession() {
    if (sessionIsValid()) {
        return true;
    }
    sendSecurityHeaders();
    webServer.sendHeader("Location", "/login", true);
    webServer.send(302, "text/plain", "需要登录");
    return false;
}

bool hasConfig();

void markConfigActivity() {
    lastConfigActivityAt = millis();
}

bool configModeExpired() {
    return configMode && hasConfig() && millis() - lastConfigActivityAt >= kConfigModeTimeoutMs;
}

void setLed(bool on) {
    digitalWrite(kLedPin, on ? LOW : HIGH);
}

uint8_t wifiCount() {
    uint8_t count = 0;
    while (count < kMaxWifiNetworks && config.wifi[count].ssid[0] != '\0') ++count;
    return count;
}

uint8_t serverCount() {
    uint8_t count = 0;
    while (count < kMaxServers && config.servers[count].wsUrl[0] != '\0') ++count;
    return count;
}

bool hasConfig() {
    return wifiCount() > 0 && serverCount() > 0 && config.deviceId[0] != '\0';
}

void copyField(char* destination, size_t capacity, const String& value) {
    value.toCharArray(destination, capacity);
    destination[capacity - 1] = '\0';
}

bool legacyConfig = false;

void loadConfig() {
    EEPROM.begin(kEepromSize);
    StoredConfig stored{};
    EEPROM.get(0, stored);
    legacyConfig = stored.magic == 0x52454331;
    if (stored.magic == kConfigMagic) {
        config = stored.config;
    } else if (stored.magic == kPreviousConfigMagic || stored.magic == kOlderConfigMagic || legacyConfig) {
        LegacyStoredConfig legacy{};
        EEPROM.get(0, legacy);
        memset(&config, 0, sizeof(config));
        copyField(config.wifi[0].ssid, sizeof(config.wifi[0].ssid), legacy.config.wifiSsid);
        copyField(config.wifi[0].password, sizeof(config.wifi[0].password), legacy.config.wifiPassword);
        copyField(config.servers[0].wsUrl, sizeof(config.servers[0].wsUrl), legacy.config.wsUrl);
        copyField(config.servers[0].token, sizeof(config.servers[0].token), legacy.config.token);
        copyField(config.deviceId, sizeof(config.deviceId), legacy.config.deviceId);
        copyField(config.passwordHash, sizeof(config.passwordHash), legacy.config.passwordHash);
        config.uploadIntervalSeconds = legacy.config.uploadIntervalSeconds;
        if (legacyConfig) memset(config.passwordHash, 0, sizeof(config.passwordHash));
    } else {
        memset(&config, 0, sizeof(config));
        config.uploadIntervalSeconds = kDefaultUploadIntervalSeconds;
    }
    for (uint8_t i = 0; i < kMaxWifiNetworks; ++i) {
        config.wifi[i].ssid[sizeof(config.wifi[i].ssid) - 1] = '\0';
        config.wifi[i].password[sizeof(config.wifi[i].password) - 1] = '\0';
    }
    for (uint8_t i = 0; i < kMaxServers; ++i) {
        config.servers[i].wsUrl[sizeof(config.servers[i].wsUrl) - 1] = '\0';
        config.servers[i].token[sizeof(config.servers[i].token) - 1] = '\0';
    }
        config.deviceId[sizeof(config.deviceId) - 1] = '\0';
        config.passwordHash[sizeof(config.passwordHash) - 1] = '\0';
    if (config.uploadIntervalSeconds < kMinimumUploadIntervalSeconds || config.uploadIntervalSeconds > kMaximumUploadIntervalSeconds) {
        config.uploadIntervalSeconds = kDefaultUploadIntervalSeconds;
    }
    uploadIntervalSeconds = config.uploadIntervalSeconds;
}

void loadSequences() {
    if (!sequencePreferences.begin("sequences", false)) {
        addLog("序列号存储初始化失败，将使用当前时间兜底");
        return;
    }
    bluetoothSequence = sequencePreferences.getULong64("bluetooth", 0);
    wifiSequence = sequencePreferences.getULong64("wifi", 0);
}

uint64_t nextSequence(uint64_t& lastSequence, const char* key, uint64_t now) {
    const uint64_t candidate = lastSequence == UINT64_MAX ? UINT64_MAX : lastSequence + 1;
    lastSequence = now > candidate ? now : candidate;
    sequencePreferences.putULong64(key, lastSequence);
    return lastSequence;
}

void saveConfig() {
    StoredConfig stored{ kConfigMagic, config };
    EEPROM.put(0, stored);
    EEPROM.commit();
}

bool parseWsUrl(const char* url, String& host, uint16_t& port, String& path, bool& secure) {
    String value(url);
    value.trim();
    secure = value.startsWith("wss://");
    const String scheme = secure ? "wss://" : "ws://";
    if (!value.startsWith(scheme)) {
        return false;
    }

    String authorityAndPath = value.substring(scheme.length());
    const int slash = authorityAndPath.indexOf('/');
    String authority = slash >= 0 ? authorityAndPath.substring(0, slash) : authorityAndPath;
    path = slash >= 0 ? authorityAndPath.substring(slash) : "/";
    if (authority.length() == 0 || path[0] != '/') {
        return false;
    }

    const int colon = authority.lastIndexOf(':');
    if (colon > 0 && authority.indexOf(']') < colon) {
        host = authority.substring(0, colon);
        const long parsedPort = authority.substring(colon + 1).toInt();
        if (parsedPort < 1 || parsedPort > 65535) {
            return false;
        }
        port = static_cast<uint16_t>(parsedPort);
    } else {
        host = authority;
        port = secure ? 443 : 80;
    }
    return host.length() > 0;
}

void sendAuth(uint8_t serverIndex) {
    StaticJsonDocument<512> message;
    message["type"] = "auth";
    message["role"] = "collector";
    message["token"] = config.servers[serverIndex].token;
    message["device_id"] = config.deviceId;
    JsonObject device = message["device"].to<JsonObject>();
    device["name"] = "ESP32-C3 WiFi/Bluetooth Collector";
    device["device_type"] = "esp32-c3";
    JsonArray capabilities = device["capabilities"].to<JsonArray>();
    capabilities.add("wifi");
    capabilities.add("bluetooth");

    String payload;
    serializeJson(message, payload);
    websockets[serverIndex].sendTXT(payload);
    addLog(String("服务器 ") + (serverIndex + 1) + " 发送 WebSocket 认证");
}

uint64_t currentEpochMillis() {
    timeval currentTime{};
    gettimeofday(&currentTime, nullptr);
    const uint64_t seconds = static_cast<uint64_t>(currentTime.tv_sec);
    if (seconds < static_cast<uint64_t>(kMinimumValidEpoch)) {
        return 0;
    }
    return seconds * 1000ULL + static_cast<uint64_t>(currentTime.tv_usec / 1000);
}

void blinkConnected() {
    bool connected = false;
    for (uint8_t i = 0; i < kMaxServers; ++i) connected |= serverAuthenticated[i] && websockets[i].isConnected();
    if (!connected) {
        return;
    }
    setLed(true);
    delay(80);
    setLed(false);
}

String base64Encode(const uint8_t* data, size_t length) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    String output;
    output.reserve(((length + 2) / 3) * 4);
    for (size_t i = 0; i < length; i += 3) {
        const uint32_t value = (static_cast<uint32_t>(data[i]) << 16) |
            (i + 1 < length ? static_cast<uint32_t>(data[i + 1]) << 8 : 0) |
            (i + 2 < length ? data[i + 2] : 0);
        output += alphabet[(value >> 18) & 63];
        output += alphabet[(value >> 12) & 63];
        output += i + 1 < length ? alphabet[(value >> 6) & 63] : '=';
        output += i + 2 < length ? alphabet[value & 63] : '=';
    }
    return output;
}

String bytesToHex(const uint8_t* data, size_t length) {
    String output;
    output.reserve(length * 2);
    for (size_t i = 0; i < length; ++i) {
        if (data[i] < 16) output += '0';
        output += String(data[i], HEX);
    }
    return output;
}
uint64_t currentEpochMillis();
void blinkConnected();
String base64Encode(const uint8_t* data, size_t length);

void scanBluetoothSnapshot(uint32_t durationMs) {
    const uint64_t scanStartedAt = currentEpochMillis();
    NimBLEScan* scanner = NimBLEDevice::getScan();
    scanner->setActiveScan(true);
    scanner->setInterval(100);
    scanner->setWindow(100);
    scanner->setMaxResults(100);
    scanner->setDuplicateFilter(1);
    NimBLEScanResults results = scanner->getResults(durationMs, false);
    addLog(String("Bluetooth 扫描完成：") + results.getCount() + " 个");

    static DynamicJsonDocument document(12288);
    document.clear();
    JsonArray devices = document["devices"].to<JsonArray>();
    const int count = results.getCount();
    for (int i = 0; i < count; ++i) {
        const NimBLEAdvertisedDevice* device = results.getDevice(i);
        JsonObject item = devices.add<JsonObject>();
        item["name"] = device->haveName() ? device->getName().c_str() : "";
        item["address"] = device->getAddress().toString().c_str();
        item["rssi"] = device->getRSSI();
        item["address_type"] = "unknown";

        if (device->haveTXPower()) item["tx_power"] = device->getTXPower();
        if (device->haveServiceUUID()) {
            JsonArray uuids = item["service_uuids"].to<JsonArray>();
            for (int j = 0; j < device->getServiceUUIDCount(); ++j) {
                uuids.add(device->getServiceUUID(j).toString().c_str());
            }

        }
        if (device->haveServiceData()) {
            JsonObject serviceData = item["service_data"].to<JsonObject>();
            for (uint8_t j = 0; j < device->getServiceDataCount(); ++j) {
                const std::string raw = device->getServiceData(j);
                serviceData[device->getServiceDataUUID(j).toString().c_str()] =
                    base64Encode(reinterpret_cast<const uint8_t*>(raw.data()), raw.length());
            }
        }
        if (device->haveManufacturerData()) {
            const std::string raw = device->getManufacturerData(0);
            if (raw.length() >= 2) {
                item["manufacturer_id"] = static_cast<uint16_t>(static_cast<uint8_t>(raw[0])) |
                    (static_cast<uint16_t>(static_cast<uint8_t>(raw[1])) << 8);
            }
            item["manufacturer_data"] = base64Encode(
                reinterpret_cast<const uint8_t*>(raw.data()), raw.length());
        }
        const std::vector<uint8_t>& rawAdvertisement = device->getPayload();
        item["rawHex"] = bytesToHex(rawAdvertisement.data(), rawAdvertisement.size());
        item["rawLength"] = rawAdvertisement.size();
        item["raw"] = base64Encode(rawAdvertisement.data(), rawAdvertisement.size());
        item["timestamp"] = currentEpochMillis();
    }
    document["scan_started_at"] = scanStartedAt;
    document["scan_finished_at"] = currentEpochMillis();
    document["technology"] = "ble";
    document["is_enabled"] = true;
    String encoded;
    serializeJson(document, encoded);
    if (encoded.length() < sizeof(bluetoothSnapshot)) {
        encoded.toCharArray(bluetoothSnapshot, sizeof(bluetoothSnapshot));
        bluetoothSnapshotLength = encoded.length();
        bluetoothSnapshotAt = currentEpochMillis();
        bluetoothSnapshotReady = true;
    }
    scanner->clearResults();
}

void scanWifiSnapshot(uint32_t durationMs) {
    const uint64_t scanStartedAt = currentEpochMillis();
    const uint32_t perChannelMs = max<uint32_t>(100, durationMs / 14);
    const int count = WiFi.scanNetworks(false, true, false, perChannelMs);
    addLog(String("WiFi 扫描完成：") + count + " 个");
    static DynamicJsonDocument document(8192);
    document.clear();
    JsonArray networks = document["networks"].to<JsonArray>();
    for (int i = 0; i < count; ++i) {
        JsonObject network = networks.add<JsonObject>();
        network["ssid"] = WiFi.SSID(i);
        network["bssid"] = WiFi.BSSIDstr(i);
        network["rssi"] = WiFi.RSSI(i);
        network["channel"] = WiFi.channel(i);
        network["frequency_mhz"] = WiFi.channel(i) <= 14 ? 2407 + WiFi.channel(i) * 5 : 5000 + WiFi.channel(i) * 5;
        JsonArray security = network["security"].to<JsonArray>();
        security.add(WiFi.encryptionType(i) == WIFI_AUTH_OPEN ? "OPEN" : "WPA2-PSK");
        network["hidden"] = WiFi.SSID(i).length() == 0;
        network["timestamp"] = currentEpochMillis();
    }
    document["scan_started_at"] = scanStartedAt;
    document["scan_finished_at"] = currentEpochMillis();
    document["interface"] = "wlan0";
    document["is_connected"] = WiFi.status() == WL_CONNECTED;
    if (WiFi.status() == WL_CONNECTED) {
        document["ip_address"] = WiFi.localIP().toString();
        document["gateway"] = WiFi.gatewayIP().toString();
        JsonArray dnsServers = document["dns_servers"].to<JsonArray>();
        dnsServers.add(WiFi.dnsIP().toString());
    }
    String encoded;
    serializeJson(document, encoded);
    if (encoded.length() < sizeof(wifiSnapshot)) {
        encoded.toCharArray(wifiSnapshot, sizeof(wifiSnapshot));
        wifiSnapshotLength = encoded.length();
        wifiSnapshotAt = currentEpochMillis();
        wifiSnapshotReady = true;
    }
    WiFi.scanDelete();
}

void runScanCycle() {
    const uint32_t intervalMs = constrain(uploadIntervalSeconds, kMinimumUploadIntervalSeconds, kMaximumUploadIntervalSeconds) * 1000UL;
    const uint32_t bluetoothMs = intervalMs / 2;
    const uint32_t wifiMs = intervalMs - bluetoothMs;
    addLog(String("开始扫描周期：Bluetooth ") + bluetoothMs / 1000 + " 秒，WiFi " + wifiMs / 1000 + " 秒");
    scanBluetoothSnapshot(bluetoothMs);
    scanWifiSnapshot(wifiMs);
}

void startWebSocket(uint8_t serverIndex);
void maintainWebSocket();
void onWebSocketEvent(uint8_t serverIndex, WStype_t type, uint8_t* payload, size_t length);
void onWebSocketEvent0(WStype_t type, uint8_t* payload, size_t length);
void onWebSocketEvent1(WStype_t type, uint8_t* payload, size_t length);
void onWebSocketEvent2(WStype_t type, uint8_t* payload, size_t length);

void sendEnvironmentData(const char* dataType, const char* dataJson, uint64_t sequence, uint64_t timestamp) {
    static DynamicJsonDocument message(16384);
    message.clear();
    message["type"] = "environment_data";
    message["version"] = 1;
    message["device_id"] = config.deviceId;
    message["data_type"] = dataType;
    message["timestamp"] = timestamp;
    message["sequence"] = sequence;
    static StaticJsonDocument<12288> data;
    data.clear();
    if (deserializeJson(data, dataJson) != DeserializationError::Ok) {
        addLog(String("数据解析失败：") + dataType);
        return;
    }
    message["data"] = data.as<JsonObject>();
    String payload;
    serializeJson(message, payload);
    for (uint8_t i = 0; i < kMaxServers; ++i) {
        if (!serverAuthenticated[i] || !websockets[i].isConnected()) continue;
        const bool sent = websockets[i].sendTXT(payload);
        addLog(String("服务器 ") + (i + 1) + " 上传 " + dataType + (sent ? " 已发送" : " 发送失败"));
    }
}

void sendCombinedSnapshot() {
    bool anyServerReady = false;
    for (uint8_t i = 0; i < kMaxServers; ++i) anyServerReady |= serverAuthenticated[i] && websockets[i].isConnected();
    if (!anyServerReady) {
        addLog("组合上传跳过：没有已认证服务器");
        return;
    }
    const uint64_t timestamp = currentEpochMillis();
    if (timestamp == 0) return;
    String wifiCopy(wifiSnapshot);
    String bluetoothCopy(bluetoothSnapshot);
    const bool wifiReady = wifiSnapshotReady;
    const bool bluetoothReady = bluetoothSnapshotReady;
    if (!wifiReady) wifiCopy = "{\"networks\":[]}";
    if (!bluetoothReady) bluetoothCopy = "{\"devices\":[]}";
    const uint64_t nextBluetoothSequence = nextSequence(bluetoothSequence, "bluetooth", timestamp);
    const uint64_t nextWifiSequence = nextSequence(wifiSequence, "wifi", timestamp);
    sendEnvironmentData(kBluetoothDataType, bluetoothCopy.c_str(), nextBluetoothSequence, timestamp);
    sendEnvironmentData(kWifiDataType, wifiCopy.c_str(), nextWifiSequence, timestamp);
}


void onWebSocketEvent(uint8_t serverIndex, WStype_t type, uint8_t* payload, size_t length) {
    switch (type) {
        case WStype_CONNECTED:
            serverAuthenticated[serverIndex] = false;
            connectedAt[serverIndex] = millis();
            lastApplicationPingAt[serverIndex] = millis() + kApplicationPingIntervalMs;
            addLog(String("服务器 ") + (serverIndex + 1) + " WebSocket 已连接，发送认证");
            sendAuth(serverIndex);
            break;
        case WStype_DISCONNECTED:
            serverAuthenticated[serverIndex] = false;
            connectedAt[serverIndex] = 0;
            webSocketStarted[serverIndex] = false;
            nextWebSocketRetryAt[serverIndex] = millis() + kWebSocketRetryIntervalMs;
            addLog(String("服务器 ") + (serverIndex + 1) + " WebSocket 已断开，等待重连");
            break;
        case WStype_PONG:
            addLog("收到 WebSocket Pong");
            break;
        case WStype_TEXT: {
            StaticJsonDocument<1024> message;
            if (deserializeJson(message, payload, length) != DeserializationError::Ok) {
                addLog("收到无效的服务端 JSON");
                break;
            }
            const char* messageType = message["type"] | "";
            if (strcmp(messageType, "auth_result") == 0) {
                serverAuthenticated[serverIndex] = message["success"] | false;
                addLog(String("服务器 ") + (serverIndex + 1) + (serverAuthenticated[serverIndex] ? " WebSocket 认证成功" : " WebSocket 认证失败"));
            } else if (strcmp(messageType, "ping") == 0) {
                websockets[serverIndex].sendTXT("{\"type\":\"ping\"}");
                addLog("收到应用层 Ping，已回复");
            }
            break;
        }
        default:
            break;
    }
}

void onWebSocketEvent0(WStype_t type, uint8_t* payload, size_t length) { onWebSocketEvent(0, type, payload, length); }
void onWebSocketEvent1(WStype_t type, uint8_t* payload, size_t length) { onWebSocketEvent(1, type, payload, length); }
void onWebSocketEvent2(WStype_t type, uint8_t* payload, size_t length) { onWebSocketEvent(2, type, payload, length); }

String htmlEscape(const char* value) {
    String result(value);
    result.replace("&", "&amp;");
    result.replace("<", "&lt;");
    result.replace(">", "&gt;");
    result.replace("\"", "&quot;");
    result.replace("'", "&#39;");
    return result;
}

String htmlEscape(const String& value) {
    return htmlEscape(value.c_str());
}

void sendLoginPage(const String& error = "") {
    String page;
    page.reserve(2800);
    page += F("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>RemoteEnv 登录</title><style>body{font-family:system-ui,sans-serif;background:#f3f5f7;margin:0;padding:24px;color:#17202a}main{max-width:460px;margin:auto;background:white;padding:24px;border-radius:12px;box-shadow:0 4px 18px #0002}label{display:block;margin-top:16px;font-weight:600}input{box-sizing:border-box;width:100%;padding:11px;margin-top:6px;border:1px solid #bbc4cc;border-radius:7px;font-size:15px}button{width:100%;margin-top:24px;padding:12px;border:0;border-radius:7px;background:#1769aa;color:white;font-size:16px}.error{color:#b42318}</style></head><body><main><h1>ESP32-C3 管理登录</h1>");
    if (error.length()) { page += F("<p class='error'>"); page += htmlEscape(error); page += F("</p>"); }
    page += F("<form method='post' action='/login'><label>管理密码<input name='password' type='password' minlength='8' maxlength='96' required autofocus></label><button type='submit'>登录</button></form></main></body></html>");
    sendSecurityHeaders();
    webServer.send(200, "text/html; charset=utf-8", page);
}

void handleLogin() {
    markConfigActivity();
    if (!hasAdminPassword()) {
        sendSecurityHeaders();
        webServer.sendHeader("Location", "/setup-password", true);
        webServer.send(302, "text/plain", "请先设置管理密码");
        return;
    }
    if (!webServer.hasArg("password") || webServer.arg("password").length() < 8 ||
        !constantTimeEquals(config.passwordHash, passwordDigest(webServer.arg("password")))) {
        sendLoginPage("密码错误");
        return;
    }
    createSession();
    sendSecurityHeaders();
    webServer.sendHeader("Set-Cookie", String("REMOTENV_SESSION=") + sessionToken + "; Max-Age=1800; HttpOnly; SameSite=Strict; Path=/", true);
    webServer.sendHeader("Location", "/panel", true);
    webServer.send(302, "text/plain", "登录成功");
}

void handleConfigPage();

void handleSetupPassword() {
    markConfigActivity();
    if (hasAdminPassword()) {
        if (!requireSession()) return;
        handleConfigPage();
        return;
    }
    String page;
    page.reserve(2800);
    page += F("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>设置管理密码</title><style>body{font-family:system-ui,sans-serif;background:#f3f5f7;margin:0;padding:24px;color:#17202a}main{max-width:520px;margin:auto;background:white;padding:24px;border-radius:12px;box-shadow:0 4px 18px #0002}label{display:block;margin-top:16px;font-weight:600}input{box-sizing:border-box;width:100%;padding:11px;margin-top:6px;border:1px solid #bbc4cc;border-radius:7px;font-size:15px}button{width:100%;margin-top:24px;padding:12px;border:0;border-radius:7px;background:#1769aa;color:white;font-size:16px}p{color:#5d6872}</style></head><body><main><h1>首次设置管理密码</h1><p>密码至少 8 位。设置后，配置页、运行面板和保存接口都必须登录。</p><form method='post' action='/setup-password'><label>管理密码<input name='password' type='password' minlength='8' maxlength='96' required></label><label>确认密码<input name='confirm' type='password' minlength='8' maxlength='96' required></label><button type='submit'>设置密码</button></form></main></body></html>");
    sendSecurityHeaders();
    webServer.send(200, "text/html; charset=utf-8", page);
}

void handleSetupPasswordPost() {
    if (hasAdminPassword()) {
        if (!requireSession()) return;
        webServer.send(403, "text/plain; charset=utf-8", "管理密码已经设置");
        return;
    }
    const String password = webServer.arg("password");
    if (password.length() < 8 || password.length() > 96 || password != webServer.arg("confirm")) {
        handleSetupPassword();
        return;
    }
    copyField(config.passwordHash, sizeof(config.passwordHash), passwordDigest(password));
    saveConfig();
    createSession();
    sendSecurityHeaders();
    webServer.sendHeader("Set-Cookie", String("REMOTENV_SESSION=") + sessionToken + "; Max-Age=1800; HttpOnly; SameSite=Strict; Path=/", true);
    webServer.sendHeader("Location", "/", true);
    webServer.send(302, "text/plain", "密码已设置");
}

void handleLogout() {
    sessionToken = "";
    sessionCreatedAt = 0;
    sendSecurityHeaders();
    webServer.sendHeader("Set-Cookie", "REMOTENV_SESSION=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/", true);
    webServer.sendHeader("Location", "/login", true);
    webServer.send(302, "text/plain", "已退出");
}

void handleConfigPage() {
    markConfigActivity();
    if (!hasAdminPassword()) {
        sendSecurityHeaders();
        webServer.sendHeader("Location", "/setup-password", true);
        webServer.send(302, "text/plain", "请先设置管理密码");
        return;
    }
    if (!requireSession()) return;
    String page;
    page.reserve(5000);
    page += F("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>RemoteEnv 配置</title><style>body{font-family:system-ui,sans-serif;background:#f3f5f7;margin:0;padding:24px;color:#17202a}main{max-width:560px;margin:auto;background:white;padding:24px;border-radius:12px;box-shadow:0 4px 18px #0002}h1{font-size:22px}label{display:block;margin-top:16px;font-weight:600}input{box-sizing:border-box;width:100%;padding:11px;margin-top:6px;border:1px solid #bbc4cc;border-radius:7px;font-size:15px}button{width:100%;margin-top:24px;padding:12px;border:0;border-radius:7px;background:#1769aa;color:white;font-size:16px}a{color:#1769aa}p{color:#5d6872;font-size:14px;line-height:1.5}</style></head><body><main><h1>ESP32-C3 环境采集器配置</h1><p>保存后设备会自动重启。WS 地址支持 ws:// 和 wss://。</p><form method='post' action='/save'>");
    page += F("<h2>WiFi 列表（最多 5 个，按顺序尝试）</h2>");
    for (uint8_t i = 0; i < kMaxWifiNetworks; ++i) {
        page += F("<fieldset><legend>WiFi "); page += i + 1; page += F("</legend><label>名称<input name='ssid"); page += i; page += F("' maxlength='63' value='"); page += htmlEscape(config.wifi[i].ssid); page += F("'></label><label>密码<input name='password"); page += i; page += F("' type='password' maxlength='63' value='"); page += htmlEscape(config.wifi[i].password); page += F("'></label></fieldset>");
    }
    page += F("<h2>服务器列表（最多 3 个，并行独立连接）</h2>");
    for (uint8_t i = 0; i < kMaxServers; ++i) {
        page += F("<fieldset><legend>服务器 "); page += i + 1; page += F("</legend><label>WS 地址<input name='ws"); page += i; page += F("' maxlength='159' value='"); page += htmlEscape(config.servers[i].wsUrl); page += F("'></label><label>Token<input name='token"); page += i; page += F("' maxlength='159' value='"); page += htmlEscape(config.servers[i].token); page += F("'></label></fieldset>");
    }
    page += F("<label>设备 ID<input name='device' maxlength='63' required value='"); page += htmlEscape(config.deviceId); page += F("'></label><label>上传间隔（秒，10-30）<input name='interval' type='number' min='10' max='30' required value='"); page += uploadIntervalSeconds; page += F("'></label><label>新管理密码<input name='newPassword' type='password' minlength='8' maxlength='96' placeholder='留空则保持不变'></label><label>确认新管理密码<input name='confirmPassword' type='password' minlength='8' maxlength='96' placeholder='留空则保持不变'></label><button type='submit'>保存配置</button></form><p><a href='/panel'>打开运行面板</a> · <form method='post' action='/logout' style='display:inline'><button type='submit' style='width:auto;margin:0;padding:4px 10px;background:#68737d'>退出登录</button></form></p></main></body></html>");
    webServer.send(200, "text/html; charset=utf-8", page);
}

void handlePanel() {
    markConfigActivity();
    if (!hasAdminPassword()) {
        sendSecurityHeaders();
        webServer.sendHeader("Location", "/setup-password", true);
        webServer.send(302, "text/plain", "请先设置管理密码");
        return;
    }
    if (!requireSession()) return;
    String page;
    page.reserve(5000);
    page += F("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><meta http-equiv='refresh' content='5'><title>RemoteEnv 面板</title><style>body{font-family:system-ui,sans-serif;background:#f3f5f7;margin:0;padding:24px;color:#17202a}main{max-width:760px;margin:auto;background:white;padding:24px;border-radius:12px;box-shadow:0 4px 18px #0002}h1{font-size:22px}pre{white-space:pre-wrap;background:#101820;color:#d8f3dc;padding:16px;border-radius:8px;min-height:180px}a{color:#1769aa}.ok{color:#087f23}.bad{color:#b42318}</style></head><body><main><h1>ESP32-C3 运行面板</h1>");
    page += F("<p>模式："); page += configMode ? F("配置 AP") : F("联网采集");
    page += F("<br>WiFi："); page += WiFi.status() == WL_CONNECTED ? F("已连接 ") : F("未连接 ");
    page += WiFi.localIP().toString();
    page += F("<br>服务器：");
    for (uint8_t i = 0; i < serverCount(); ++i) {
        page += String(i + 1) + (serverAuthenticated[i] && websockets[i].isConnected() ? " 已认证" : " 未连接/未认证");
        if (i + 1 < serverCount()) page += ", ";
    }
    page += F("<br>设备 ID："); page += htmlEscape(config.deviceId); page += F("</p><p>扫描与上传间隔："); page += uploadIntervalSeconds; page += F(" 秒</p><h2>最近日志</h2><pre>");
    for (uint8_t i = 0; i < logCount; ++i) { page += htmlEscape(String(logLines[i])); page += '\n'; }
    page += F("</pre><p><a href='/'>配置页面</a> · <form method='post' action='/logout' style='display:inline'><button type='submit' style='width:auto;margin:0;padding:4px 10px;background:#68737d'>退出登录</button></form></p></main></body></html>");
    webServer.send(200, "text/html; charset=utf-8", page);
}

void handleSaveConfig() {
    markConfigActivity();
    if (!hasAdminPassword()) {
        webServer.send(403, "text/plain; charset=utf-8", "请先设置管理密码");
        return;
    }
    if (!requireSession()) return;
    if (!webServer.hasArg("device") || !webServer.hasArg("interval")) {
        webServer.send(400, "text/plain; charset=utf-8", "缺少配置字段");
        return;
    }
    DeviceConfig requested{};
    uint8_t wifiWriteIndex = 0;
    for (uint8_t i = 0; i < kMaxWifiNetworks; ++i) {
        const String ssid = webServer.arg(String("ssid") + i);
        const String password = webServer.arg(String("password") + i);
        if (ssid.length() == 0) continue;
        copyField(requested.wifi[wifiWriteIndex].ssid, sizeof(requested.wifi[wifiWriteIndex].ssid), ssid);
        copyField(requested.wifi[wifiWriteIndex].password, sizeof(requested.wifi[wifiWriteIndex].password), password);
        ++wifiWriteIndex;
    }
    uint8_t serverWriteIndex = 0;
    for (uint8_t i = 0; i < kMaxServers; ++i) {
        const String ws = webServer.arg(String("ws") + i);
        const String token = webServer.arg(String("token") + i);
        if (ws.length() == 0 && token.length() == 0) continue;
        String host, path;
        uint16_t port = 0;
        bool secure = false;
        if (!parseWsUrl(ws.c_str(), host, port, path, secure) || token.length() == 0 || serverWriteIndex >= kMaxServers) {
            webServer.send(400, "text/plain; charset=utf-8", "每个服务器必须包含有效 WS 地址和 Token");
            return;
        }
        copyField(requested.servers[serverWriteIndex].wsUrl, sizeof(requested.servers[serverWriteIndex].wsUrl), ws);
        copyField(requested.servers[serverWriteIndex].token, sizeof(requested.servers[serverWriteIndex].token), token);
        ++serverWriteIndex;
    }
    if (wifiWriteIndex == 0) {
        webServer.send(400, "text/plain; charset=utf-8", "至少配置一个 WiFi");
        return;
    }
    if (serverWriteIndex == 0) {
        webServer.send(400, "text/plain; charset=utf-8", "至少配置一个服务器");
        return;
    }
    copyField(requested.deviceId, sizeof(requested.deviceId), webServer.arg("device"));
    if (requested.deviceId[0] == '\0') {
        webServer.send(400, "text/plain; charset=utf-8", "设备 ID 不能为空");
        return;
    }
    copyField(requested.passwordHash, sizeof(requested.passwordHash), config.passwordHash);
    const long requestedInterval = webServer.arg("interval").toInt();
    if (requestedInterval < static_cast<long>(kMinimumUploadIntervalSeconds) ||
        requestedInterval > static_cast<long>(kMaximumUploadIntervalSeconds)) {
        webServer.send(400, "text/plain; charset=utf-8", "上传间隔必须是 5 到 30 秒");
        return;
    }
    uploadIntervalSeconds = static_cast<uint32_t>(requestedInterval);
    requested.uploadIntervalSeconds = uploadIntervalSeconds;
    const String newPassword = webServer.arg("newPassword");
    const String confirmPassword = webServer.arg("confirmPassword");
    if (newPassword.length() > 0) {
        if (newPassword.length() < 8 || newPassword.length() > 96 || newPassword != confirmPassword) {
            webServer.send(400, "text/plain; charset=utf-8", "新管理密码无效或两次输入不一致");
            return;
        }
        copyField(requested.passwordHash, sizeof(requested.passwordHash), passwordDigest(newPassword));
    }
    config = requested;
    saveConfig();
    sessionToken = "";
    sendSecurityHeaders();
    webServer.send(200, "text/html; charset=utf-8", "<meta charset='utf-8'><p>配置已保存，管理会话已失效，请重新登录。设备正在重启...</p>");
    delay(800);
    ESP.restart();
}

void registerWebRoutes() {
    if (webRoutesRegistered) return;
    webRoutesRegistered = true;
    const char* headerKeys[] = {"Cookie"};
    webServer.collectHeaders(headerKeys, 1);
    webServer.on("/", HTTP_GET, handleConfigPage);
    webServer.on("/login", HTTP_GET, []() { sendLoginPage(); });
    webServer.on("/login", HTTP_POST, handleLogin);
    webServer.on("/setup-password", HTTP_GET, handleSetupPassword);
    webServer.on("/setup-password", HTTP_POST, handleSetupPasswordPost);
    webServer.on("/logout", HTTP_POST, handleLogout);
    webServer.on("/panel", HTTP_GET, handlePanel);
    webServer.on("/save", HTTP_POST, handleSaveConfig);
    webServer.onNotFound([]() { webServer.send(404, "text/plain; charset=utf-8", "Not found"); });
}

void startLocalWebServer() {
    registerWebRoutes();
    if (!webServerStarted) {
        webServer.begin();
        webServerStarted = true;
    }
    addLog(String("局域网面板：http://") + WiFi.localIP().toString() + "/panel");
}

void startConfigMode() {
    if (configMode) {
        return;
    }
    configMode = true;
    configModeStartedAt = millis();
    lastConfigActivityAt = configModeStartedAt;
    for (uint8_t i = 0; i < kMaxServers; ++i) {
        serverAuthenticated[i] = false;
        websockets[i].disconnect();
        webSocketStarted[i] = false;
    }
    setLed(true);
    WiFi.disconnect(true);
    WiFi.mode(WIFI_AP);
    const String apName = String("RemoteEnv-Setup-") + String(getChipIdHex());
    WiFi.softAP(apName.c_str(), kApPassword);
    registerWebRoutes();
    if (!webServerStarted) {
        webServer.begin();
        webServerStarted = true;
    }
    addLog(String("配置 AP：") + apName + "，访问 http://" + WiFi.softAPIP().toString() + "/");
}

void beginWifiAttempt() {
    WiFi.mode(WIFI_STA);
    WiFi.begin(config.wifi[wifiIndex].ssid, config.wifi[wifiIndex].password);
    wifiAttemptStartedAt = millis();
    wifiConnecting = true;
    addLog(String("尝试连接 WiFi ") + (wifiIndex + 1) + "：" + config.wifi[wifiIndex].ssid);
}

void maintainWifi() {
    const uint32_t now = millis();
    if (WiFi.status() == WL_CONNECTED) {
        if (wifiConnecting) {
            wifiConnecting = false;
            addLog(String("WiFi 已连接：") + WiFi.localIP().toString());
            setenv("TZ", "CST-8", 1);
            tzset();
            configTime(0, 0, "ntp1.aliyun.com", "pool.ntp.org", "time.nist.gov");
            if (!webServerStarted) startLocalWebServer();
            for (uint8_t i = 0; i < kMaxServers; ++i) nextWebSocketRetryAt[i] = now;
            wifiRetryDelayMs = kWifiRetryBaseIntervalMs;
            wifiRound = 0;
        }
        return;
    }
    for (uint8_t i = 0; i < kMaxServers; ++i) {
        serverAuthenticated[i] = false;
        if (webSocketStarted[i]) {
            websockets[i].disconnect();
            webSocketStarted[i] = false;
        }
    }
    if (wifiConnecting && now - wifiAttemptStartedAt < kWifiConnectTimeoutMs) return;
    if (wifiConnecting) {
        wifiConnecting = false;
        addLog(String("WiFi ") + (wifiIndex + 1) + " 连接失败");
        WiFi.disconnect();
        ++wifiIndex;
        if (wifiIndex >= wifiCount()) {
            wifiIndex = 0;
            ++wifiRound;
            wifiRetryDelayMs = min<uint32_t>(wifiRetryDelayMs * 2, kWifiRetryMaximumIntervalMs);
            addLog(String("WiFi 第 ") + wifiRound + " 轮失败，" + wifiRetryDelayMs / 1000 + " 秒后重新尝试");
        }
    }
    if (static_cast<int32_t>(now - nextWifiRetryAt) >= 0) {
        nextWifiRetryAt = now + (wifiIndex == 0 ? wifiRetryDelayMs : 250);
        beginWifiAttempt();
    }
}

void startWebSocket(uint8_t serverIndex) {
    if (serverIndex >= serverCount() || webSocketStarted[serverIndex] || WiFi.status() != WL_CONNECTED) return;
    String host, path;
    uint16_t port = 0;
    bool secure = false;
    if (!parseWsUrl(config.servers[serverIndex].wsUrl, host, port, path, secure)) {
        addLog(String("服务器 ") + (serverIndex + 1) + " WS 地址无效");
        nextWebSocketRetryAt[serverIndex] = millis() + kWebSocketRetryIntervalMs;
        return;
    }
    if (secure) websockets[serverIndex].beginSSL(host.c_str(), port, path.c_str(), nullptr, "arduino");
    else websockets[serverIndex].begin(host.c_str(), port, path.c_str(), "arduino");
    if (serverIndex == 0) websockets[serverIndex].onEvent(onWebSocketEvent0);
    else if (serverIndex == 1) websockets[serverIndex].onEvent(onWebSocketEvent1);
    else websockets[serverIndex].onEvent(onWebSocketEvent2);
    websockets[serverIndex].setReconnectInterval(kWebSocketRetryIntervalMs);
    websockets[serverIndex].enableHeartbeat(15000, 3000, 2);
    webSocketStarted[serverIndex] = true;
    addLog(String("服务器 ") + (serverIndex + 1) + " 开始 WebSocket 无限重试");
}

void maintainWebSocket() {
    const uint32_t now = millis();
    for (uint8_t i = 0; i < kMaxServers; ++i) {
        if (i >= serverCount()) continue;
        if (websockets[i].isConnected() && !serverAuthenticated[i] && connectedAt[i] != 0 && now - connectedAt[i] >= kAuthTimeoutMs) {
            addLog(String("服务器 ") + (i + 1) + " 认证超时，主动断开");
            websockets[i].disconnect();
            connectedAt[i] = 0;
            webSocketStarted[i] = false;
        }
        if (static_cast<int32_t>(now - nextWebSocketRetryAt[i]) >= 0) {
            nextWebSocketRetryAt[i] = now + kWebSocketRetryIntervalMs;
            startWebSocket(i);
        }
        if (serverAuthenticated[i] && websockets[i].isConnected() && now - lastApplicationPingAt[i] >= kApplicationPingIntervalMs) {
            websockets[i].sendTXT("{\"type\":\"ping\"}");
            lastApplicationPingAt[i] = now;
        }
    }
}

void checkConfigButton() {
    const bool state = digitalRead(kConfigButtonPin);
    if (state != lastButtonState) {
        lastButtonState = state;
        lastButtonChangeAt = millis();
        addLog(state == LOW ? "GPIO0 按键按下" : "GPIO0 按键释放");
    }
    if (state == LOW && millis() - lastButtonChangeAt >= 40) {
        startConfigMode();
    }
}
}  // namespace

void setup() {
    Serial.begin(115200);
    delay(100);
    Serial.println("RemoteEnv ESP32-C3 boot");
    pinMode(kLedPin, OUTPUT);
    setLed(false);
    pinMode(kConfigButtonPin, INPUT_PULLUP);
    Serial.printf("LED GPIO=%u, GPIO0=%s\n", kLedPin, digitalRead(kConfigButtonPin) == LOW ? "LOW" : "HIGH");
    NimBLEDevice::init("");
    loadConfig();
    loadSequences();

    if (!hasConfig() || digitalRead(kConfigButtonPin) == LOW) {
        startConfigMode();
        return;
    }
    beginWifiAttempt();
    startLocalWebServer();
}

void loop() {
    checkConfigButton();
    if (configMode) {
        webServer.handleClient();
        if (configModeExpired()) {
            addLog("配网 5 分钟无操作，重启进入正常模式");
            delay(200);
            ESP.restart();
        }
        delay(2);
        return;
    }
    webServer.handleClient();
    maintainWifi();
    if (WiFi.status() == WL_CONNECTED) {
        for (uint8_t i = 0; i < kMaxServers; ++i) websockets[i].loop();
        maintainWebSocket();
        const uint32_t now = millis();
        if (static_cast<int32_t>(now - nextUploadAt) >= 0) {
            nextUploadAt = now + uploadIntervalSeconds * 1000UL;
            runScanCycle();
            sendCombinedSnapshot();
        }
    }
    delay(10);
}
