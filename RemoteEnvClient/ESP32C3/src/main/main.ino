#include <Arduino.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <WebServer.h>
#include <HTTPClient.h>
#include <NimBLEDevice.h>
#include <WiFi.h>
#include <WebSocketsClient.h>
#include <WiFiClientSecure.h>
#include <esp_wifi.h>
#include <esp_timer.h>
#include <mbedtls/sha256.h>
#include <sys/time.h>
#include <time.h>

#include "BeaconSimulator.h"
#include "BleAdvertiser.h"
#include "DeviceList.h"
#include "PullScheduler.h"

namespace {
constexpr uint8_t kLedPin = 8;
constexpr uint8_t kBootPin = 9;
constexpr uint8_t kMaxWifi = 5;
constexpr uint32_t kConfigTimeoutMs = 300000;
constexpr uint32_t kWifiAttemptMs = 15000;
constexpr uint32_t kWifiBackoffStartMs = 5000;
constexpr uint32_t kWifiBackoffMaxMs = 60000;
constexpr uint32_t kWsRetryStartMs = 10000;
constexpr uint32_t kWsRetryMaxMs = 60000;
constexpr uint32_t kAuthTimeoutMs = 20000;
constexpr uint32_t kPingIntervalMs = 20000;
constexpr uint32_t kPullIntervalMs = 5000;
constexpr uint32_t kMinPullIntervalSec = 1;
constexpr uint32_t kMaxPullIntervalSec = 3600;
constexpr uint32_t kPollDeadlineMs = 30000;
constexpr uint8_t kMaxSelectedWifi = 16;
constexpr uint8_t kLogCapacity = 24;
constexpr uint8_t kLogLineSize = 112;
constexpr uint16_t kSelectedWifiBufferSize = 4096;
constexpr time_t kMinimumEpoch = 1700000000;
constexpr char kApPassword[] = "12345678";
constexpr char kPrefsConfig[] = "config";
constexpr char kPrefsSelected[] = "selected";

struct Wifi {
    char ssid[64];
    char password[64];
};
struct ServerProfile {
    char ws[160];
    char token[160];
    char http[160];  // base URL for /api/devices, derived from ws
};
struct Config {
    Wifi wifi[kMaxWifi];
    ServerProfile server;
    char passwordHash[65];
    uint32_t pullIntervalSec;
};

Config config{};
Preferences configStore;
WebServer web(80);
WebSocketsClient ws;
BeaconSimulator beacon;
BleAdvertiser ble;
DeviceList deviceList;
PullScheduler pull;
String session;
uint32_t sessionAt = 0;
uint32_t configStartedAt = 0;
uint32_t lastConfigActivityAt = 0;
uint32_t wifiAttemptAt = 0;
uint32_t nextWifiAt = 0;
uint32_t wifiBackoffMs = kWifiBackoffStartMs;
uint8_t wifiIndex = 0;
uint32_t nextWsAt = 0;
uint32_t wsBackoffMs = kWsRetryStartMs;
uint32_t wsConnectedAt = 0;
uint32_t lastPingAt = 0;
uint32_t lastPullAt = 0;
uint32_t lastSelectedPullAt = 0;
uint32_t lastLatestDataAt = 0;
bool webServerStarted = false;
bool webRoutesRegistered = false;
uint8_t wifiRound = 0;
bool configMode = false;
bool wifiConnecting = false;
bool wsStarted = false;
bool authenticated = false;
char runtimeSelectedDeviceId[65] = "";
char lastSelectedSnapshot[65] = "";
char lastSelectedName[65] = "";
char lastSelectedWifiJson[kSelectedWifiBufferSize] = "";
char lastSelectedBleJson[kSelectedWifiBufferSize] = "";
char logs[kLogCapacity][kLogLineSize]{};
uint8_t logCount = 0;
String remoteDevicesJson;
bool remoteDevicesDirty = true;
uint32_t lastDeviceListUpdate = 0;
bool pullInFlight = false;
uint32_t nextPollDeadline = 0;
enum class LedMode : uint8_t { Config, Disconnected, Normal };
volatile LedMode ledMode = LedMode::Disconnected;

void logLine(const String &text) {
    Serial.println(text);
    if (logCount < kLogCapacity) {
        text.substring(0, kLogLineSize - 1).toCharArray(logs[logCount++], kLogLineSize);
        return;
    }
    for (uint8_t i = 1; i < kLogCapacity; ++i) memcpy(logs[i - 1], logs[i], kLogLineSize);
    text.substring(0, kLogLineSize - 1).toCharArray(logs[kLogCapacity - 1], kLogLineSize);
}

String escapeHtml(const char *value) {
    String r(value ? value : "");
    r.replace("&", "&amp;");
    r.replace("<", "&lt;");
    r.replace(">", "&gt;");
    r.replace("\"", "&quot;");
    r.replace("'", "&#39;");
    return r;
}

String chipId() {
    uint64_t id = ESP.getEfuseMac();
    char text[17]{};
    snprintf(text, sizeof(text), "%04x%08x", (uint16_t)(id >> 32), (uint32_t)id);
    return String(text);
}

String passwordHash(const String &password) {
    String input = chipId() + ":" + password;
    uint8_t hash[32];
    mbedtls_sha256((const unsigned char *)input.c_str(), input.length(), hash, 0);
    String out;
    out.reserve(64);
    for (uint8_t b : hash) {
        if (b < 16) out += '0';
        out += String(b, HEX);
    }
    return out;
}

bool constantEquals(const char *left, const String &right) {
    if (strlen(left) != right.length()) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < right.length(); ++i) diff |= (uint8_t)(left[i] ^ right[i]);
    return diff == 0;
}

void copyText(char *target, size_t capacity, const String &value) {
    value.toCharArray(target, capacity);
    target[capacity - 1] = 0;
}

uint8_t wifiCount() {
    uint8_t n = 0;
    while (n < kMaxWifi && config.wifi[n].ssid[0]) ++n;
    return n;
}

bool hasPassword() { return strlen(config.passwordHash) == 64; }

bool hasConfig() {
    return wifiCount() > 0 && config.server.ws[0] && config.server.token[0];
}

bool hasSelectedDevice() { return runtimeSelectedDeviceId[0] != 0; }

void touchConfig() { lastConfigActivityAt = millis(); }

bool sessionValid() {
    if (!hasPassword() || !session.length() || millis() - sessionAt > 1800000 || !web.hasHeader("Cookie")) return false;
    String cookie = web.header("Cookie");
    String expected = String("REMOTENV_SESSION=") + session;
    int p = cookie.indexOf(expected);
    if (p < 0) return false;
    int end = p + expected.length();
    bool valid = (p == 0 || cookie[p - 1] == ' ' || cookie[p - 1] == ';') &&
                 (end == cookie.length() || cookie[end] == ';');
    if (valid) {
        sessionAt = millis();
        web.sendHeader("Set-Cookie", String("REMOTENV_SESSION=") + session +
                       "; Max-Age=1800; HttpOnly; SameSite=Strict; Path=/", true);
    }
    return valid;
}

void headers() {
    web.sendHeader("Cache-Control", "no-store");
    web.sendHeader("Pragma", "no-cache");
    web.sendHeader("X-Content-Type-Options", "nosniff");
    web.sendHeader("X-Frame-Options", "DENY");
    web.sendHeader("Connection", "keep-alive");
}

bool requireLogin() {
    if (sessionValid()) return true;
    headers();
    web.sendHeader("Location", "/login", true);
    web.send(302, "text/plain; charset=utf-8", "需要登录");
    return false;
}

void createSession() {
    char value[33]{};
    for (uint8_t i = 0; i < 16; ++i) snprintf(value + i * 2, 3, "%02x", (uint8_t)esp_random());
    session = value;
    sessionAt = millis();
}

uint64_t epochMs() {
    timeval tv{};
    gettimeofday(&tv, nullptr);
    if (tv.tv_sec < kMinimumEpoch) return 0;
    return (uint64_t)tv.tv_sec * 1000ULL + tv.tv_usec / 1000;
}

void deriveHttpFromWs() {
    String wsUrl = config.server.ws;
    wsUrl.trim();
    bool secure = wsUrl.startsWith("wss://");
    String scheme = secure ? "https://" : "http://";
    String schemeWS = secure ? "wss://" : "ws://";
    if (!wsUrl.startsWith(schemeWS)) {
        config.server.http[0] = 0;
        return;
    }
    String body = wsUrl.substring(schemeWS.length());
    int slash = body.indexOf('/');
    String path = slash >= 0 ? body.substring(slash) : "/";
    if (path.startsWith("/ws")) {
        // Strip /ws or /ws/ prefix; HTTP root is at /.
        String remaining = path.substring(3);
        if (remaining.startsWith("/")) remaining = remaining.substring(1);
        if (remaining.length()) path = "/" + remaining;
        else path = "/";
    } else if (path.length() == 0) path = "/";
    String http = scheme + body.substring(0, slash) + path;
    http.toCharArray(config.server.http, sizeof(config.server.http));
    config.server.http[sizeof(config.server.http) - 1] = 0;
}

void loadConfig() {
    configStore.begin(kPrefsConfig, true);
    String json = configStore.getString("json", "");
    configStore.end();
    memset(&config, 0, sizeof(config));
    config.pullIntervalSec = kPullIntervalMs / 1000;
    if (json.length()) {
        DynamicJsonDocument doc(4096);
        if (deserializeJson(doc, json) == DeserializationError::Ok) {
            copyText(config.passwordHash, sizeof(config.passwordHash), doc["password_hash"] | "");
            for (uint8_t i = 0; i < kMaxWifi; ++i) {
                copyText(config.wifi[i].ssid, sizeof(config.wifi[i].ssid), doc["wifi"][i]["ssid"] | "");
                copyText(config.wifi[i].password, sizeof(config.wifi[i].password), doc["wifi"][i]["password"] | "");
            }
            copyText(config.server.ws, sizeof(config.server.ws), doc["server"]["ws"] | "");
            copyText(config.server.token, sizeof(config.server.token), doc["server"]["token"] | "");
            copyText(config.server.http, sizeof(config.server.http), doc["server"]["http"] | "");
            config.pullIntervalSec = doc["pull_interval_sec"] | (kPullIntervalMs / 1000);
        }
    }
    configStore.begin(kPrefsSelected, true);
    String selected = configStore.getString("device", "");
    configStore.end();
    selected.toCharArray(runtimeSelectedDeviceId, sizeof(runtimeSelectedDeviceId));
    runtimeSelectedDeviceId[sizeof(runtimeSelectedDeviceId) - 1] = 0;
    if (config.server.ws[0]) deriveHttpFromWs();
    if (config.pullIntervalSec < kMinPullIntervalSec || config.pullIntervalSec > kMaxPullIntervalSec) {
        config.pullIntervalSec = kPullIntervalMs / 1000;
    }
}

bool requireApiLogin() {
    if (sessionValid()) return true;
    headers();
    web.send(401, "application/json; charset=utf-8", "{\"error\":\"login_required\"}");
    return false;
}

void saveConfig() {
    DynamicJsonDocument doc(4096);
    doc["password_hash"] = config.passwordHash;
    JsonArray wifi = doc["wifi"].to<JsonArray>();
    for (uint8_t i = 0; i < kMaxWifi; ++i) {
        JsonObject item = wifi.add<JsonObject>();
        item["ssid"] = config.wifi[i].ssid;
        item["password"] = config.wifi[i].password;
    }
    JsonObject server = doc["server"].to<JsonObject>();
    server["ws"] = config.server.ws;
    server["token"] = config.server.token;
    server["http"] = config.server.http;
    doc["pull_interval_sec"] = config.pullIntervalSec;
    String json;
    serializeJson(doc, json);
    configStore.begin(kPrefsConfig, false);
    configStore.putString("json", json);
    configStore.end();
}

void saveSelectedDevice() {
    configStore.begin(kPrefsSelected, false);
    configStore.putString("device", String(runtimeSelectedDeviceId));
    configStore.end();
}

bool parseWs(const char *url, String &host, uint16_t &port, String &path, bool &secure) {
    String value(url);
    value.trim();
    secure = value.startsWith("wss://");
    String scheme = secure ? "wss://" : "ws://";
    if (!value.startsWith(scheme)) return false;
    String authorityPath = value.substring(scheme.length());
    int slash = authorityPath.indexOf('/');
    String authority = slash >= 0 ? authorityPath.substring(0, slash) : authorityPath;
    path = slash >= 0 ? authorityPath.substring(slash) : "/";
    if (!authority.length()) return false;
    int colon = authority.lastIndexOf(':');
    if (colon > 0 && authority.indexOf(']') < colon) {
        host = authority.substring(0, colon);
        long p = authority.substring(colon + 1).toInt();
        if (p < 1 || p > 65535) return false;
        port = (uint16_t)p;
    } else {
        host = authority;
        port = secure ? 443 : 80;
    }
    return host.length() > 0;
}

bool decodeHex(const String &hex, uint8_t *out, size_t outSize) {
    String cleaned = hex;
    cleaned.replace(":", "");
    cleaned.replace(" ", "");
    cleaned.toLowerCase();
    if (cleaned.length() != outSize * 2) return false;
    for (size_t i = 0; i < outSize; ++i) {
        out[i] = (uint8_t)strtoul(cleaned.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
    }
    return true;
}

bool decodeBase64(const String &text, std::vector<uint8_t> &out) {
    static const int8_t table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };
    out.clear();
    out.reserve(text.length() * 3 / 4);
    uint32_t buf = 0;
    int bits = 0;
    for (size_t i = 0; i < text.length(); ++i) {
        char c = text.charAt(i);
        if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
        int8_t v = table[(unsigned)c];
        if (v < 0) return false;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((uint8_t)((buf >> bits) & 0xff));
        }
    }
    return true;
}

bool extractBssid(JsonVariantConst v, uint8_t out[6]) {
    const char *s = v.as<const char *>();
    if (s) return decodeHex(String(s), out, 6);
    return false;
}

void applyWifiEnvelope(const char *deviceId, JsonVariantConst data) {
    JsonArrayConst networks = data["networks"].as<JsonArrayConst>();
    if (networks.isNull()) {
        if (hasSelectedDevice() && strcmp(runtimeSelectedDeviceId, deviceId) == 0) {
            deviceList.touchWifi(deviceId, 0);
            beacon.stop();
            lastSelectedWifiJson[0] = '[';
            lastSelectedWifiJson[1] = ']';
            lastSelectedWifiJson[2] = 0;
        }
        return;
    }
    BeaconNetwork nets[24]{};
        uint8_t count = 0;
        for (JsonVariantConst item : networks) {
            if (count >= 24) break;
            BeaconNetwork &n = nets[count];
            memset(&n, 0, sizeof(n));
            String ssid = item["ssid"].as<const char *>();
            if (!ssid.length()) continue;
            ssid.toCharArray(n.ssid, sizeof(n.ssid));
            n.ssid[sizeof(n.ssid) - 1] = 0;
            if (!extractBssid(item, n.bssid)) continue;
            ++count;
        }
        deviceList.touchWifi(deviceId, count);
        if (hasSelectedDevice() && strcmp(runtimeSelectedDeviceId, deviceId) == 0) {
            beacon.setNetworks(nets, count);
            // Render the latest wifi envelope into a small summary the management
            // page can show under the selected device card.
            DynamicJsonDocument summary(2048);
            JsonArray arr = summary.to<JsonArray>();
            for (JsonVariantConst item : networks) {
                JsonObject o = arr.add<JsonObject>();
                o["ssid"] = item["ssid"].as<const char *>();
                o["bssid"] = item["bssid"].as<const char *>();
                o["rssi"] = item["rssi"] | 0;
                o["channel"] = item["channel"] | 0;
                JsonArray sec = o["security"].to<JsonArray>();
                JsonArrayConst secSrc = item["security"].as<JsonArrayConst>();
                if (!secSrc.isNull()) {
                    for (JsonVariantConst s : secSrc) {
                        const char *sv = s.as<const char *>();
                        if (sv) sec.add(sv);
                    }
                }
            }
            String s;
            serializeJson(arr, s);
            s.toCharArray(lastSelectedWifiJson, sizeof(lastSelectedWifiJson));
            lastSelectedWifiJson[sizeof(lastSelectedWifiJson) - 1] = 0;
            copyText(lastSelectedName, sizeof(lastSelectedName), deviceId);
            lastPullAt = millis();
            nextPollDeadline = millis() + kPollDeadlineMs;
        }
    }

void applyBleEnvelope(const char *deviceId, JsonVariantConst data) {
    JsonArrayConst devices = data["devices"].as<JsonArrayConst>();
    if (devices.isNull()) {
        if (hasSelectedDevice() && strcmp(runtimeSelectedDeviceId, deviceId) == 0) {
            deviceList.touchBle(deviceId, 0);
            ble.stop();
            lastSelectedBleJson[0] = '[';
            lastSelectedBleJson[1] = ']';
            lastSelectedBleJson[2] = 0;
        }
        return;
    }
    BleBeaconDevice list[16]{};
    uint8_t count = 0;
    for (JsonVariantConst item : devices) {
        if (count >= 16) break;
        BleBeaconDevice &d = list[count];
        memset(&d, 0, sizeof(d));
        String address = item["address"] | "";
        address.toCharArray(d.address, sizeof(d.address));
        d.address[sizeof(d.address) - 1] = 0;
        String name = item["name"] | "";
        name.toCharArray(d.name, sizeof(d.name));
        d.name[sizeof(d.name) - 1] = 0;
        d.rssi = (int8_t)(item["rssi"].as<int>());
        d.txPower = (int8_t)(item["tx_power"] | 0);
        d.manufacturerId = (uint16_t)(item["manufacturer_id"].as<int>());
        JsonArrayConst svc = item["service_uuids"].as<JsonArrayConst>();
        if (!svc.isNull()) {
            for (JsonVariantConst s : svc) {
                if (d.serviceCount >= 16) break;
                String id = s | "";
                id.toCharArray(d.serviceUuids[d.serviceCount], 40);
                d.serviceUuids[d.serviceCount][39] = 0;
                ++d.serviceCount;
            }
        }
        std::vector<uint8_t> bytes;
        if (decodeBase64(item["manufacturer_data"] | "", bytes)) {
            d.manufacturerSize = min<uint16_t>(bytes.size(), sizeof(d.manufacturerData));
            memcpy(d.manufacturerData, bytes.data(), d.manufacturerSize);
        }
        // BLE raw payload preservation: accept either `raw` (base64) or
        // `rawHex` (hex string). The simulator forwards these verbatim into
        // the advertisement stream so vendor AD records are not lost.
        std::vector<uint8_t> rawBytes;
        bool rawOk = false;
        if (item["raw"].is<const char *>()) {
            rawOk = decodeBase64(item["raw"] | "", rawBytes);
        } else {
            String rawHex = item["rawHex"] | "";
            if (rawHex.length()) {
                rawBytes.resize(rawHex.length() / 2);
                for (size_t i = 0; i < rawBytes.size(); ++i) {
                    rawBytes[i] = (uint8_t)strtoul(rawHex.substring(i * 2, i * 2 + 2).c_str(), nullptr, 16);
                }
                rawOk = true;
            }
        }
        if (rawOk) {
            d.payloadSize = min<uint16_t>(rawBytes.size(), sizeof(d.raw));
            memcpy(d.raw, rawBytes.data(), d.payloadSize);
        } else {
            d.payloadSize = 0;
        }
        ++count;
    }
    deviceList.touchBle(deviceId, count);
    if (hasSelectedDevice() && strcmp(runtimeSelectedDeviceId, deviceId) == 0) {
        ble.setDevices(list, count);
        DynamicJsonDocument summary(4096);
        JsonArray arr = summary.to<JsonArray>();
        for (JsonVariantConst item : devices) {
            JsonObject o = arr.add<JsonObject>();
            o["address"] = item["address"] | "";
            o["name"] = item["name"] | "";
            o["rssi"] = item["rssi"] | 0;
            o["manufacturer_id"] = item["manufacturer_id"] | 0;
            o["manufacturer_data"] = item["manufacturer_data"] | "";
            o["service_uuids"] = item["service_uuids"];
            o["rawHex"] = item["rawHex"] | "";
            o["rawLength"] = item["rawLength"] | 0;
        }
        String s;
        serializeJson(arr, s);
        if (s.length() < sizeof(lastSelectedBleJson)) {
            s.toCharArray(lastSelectedBleJson, sizeof(lastSelectedBleJson));
            lastSelectedBleJson[sizeof(lastSelectedBleJson) - 1] = 0;
        }
        lastPullAt = millis();
    }
}

void sendSubscribe(const char *deviceId, bool refresh = false) {
    if (!authenticated || !ws.isConnected()) return;
    StaticJsonDocument<256> message;
    message["type"] = refresh ? "refresh" : "subscribe";
    message["device_id"] = deviceId;
    JsonArray types = message["data_types"].to<JsonArray>();
    types.add("wifi");
    types.add("bluetooth");
    String payload;
    serializeJson(message, payload);
    ws.sendTXT(payload);
    logLine(String(refresh ? "请求刷新：" : "订阅：") + deviceId);
}

void applyDeviceList(JsonArrayConst devices) {
    char previousSelection[sizeof(runtimeSelectedDeviceId)]{};
    copyText(previousSelection, sizeof(previousSelection), String(runtimeSelectedDeviceId));
    deviceList.reset();
    for (JsonVariantConst item : devices) {
        String id = item["device_id"] | "";
        if (!id.length()) continue;
        deviceList.upsert(id.c_str(), item["name"] | id.c_str(), item["online"] | false);
    }
    deviceList.sortOnlineFirst();
    remoteDevicesDirty = true;
    lastDeviceListUpdate = millis();
    if (previousSelection[0]) {
        uint8_t index = 0;
        if (deviceList.find(previousSelection, index)) {
            copyText(runtimeSelectedDeviceId, sizeof(runtimeSelectedDeviceId), String(previousSelection));
            saveSelectedDevice();
            sendSubscribe(runtimeSelectedDeviceId);
            return;
        }
        // Selection disappeared; clear the simulation.
        runtimeSelectedDeviceId[0] = 0;
        saveSelectedDevice();
        beacon.stop();
        ble.stop();
    }
    logLine(String("设备列表更新：") + deviceList.count() + " 个");
}

void sendAuth() {
    StaticJsonDocument<512> message;
    message["type"] = "auth";
    message["role"] = "consumer";
    message["token"] = config.server.token;
    JsonObject device = message["device"].to<JsonObject>();
    device["name"] = "ESP32-C3 Remote Environment Client";
    device["device_type"] = "esp32-c3";
    JsonArray capabilities = device["capabilities"].to<JsonArray>();
    capabilities.add("wifi_beacon");
    capabilities.add("bluetooth_advertise");
    String payload;
    serializeJson(message, payload);
    ws.sendTXT(payload);
    logLine("发送 Consumer 认证");
}

bool httpGet(const String &url, String &body, int &code) {
    HTTPClient http;
    http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);
    http.setTimeout(8000);
    if (!http.begin(url)) return false;
    http.addHeader("X-Admin-Token", String(config.server.token));
    code = http.GET();
    if (code > 0) body = http.getString();
    http.end();
    return code > 0;
}

void pollLatestSelected() {
    if (!hasConfig() || WiFi.status() != WL_CONNECTED || pullInFlight) return;
    if (!hasSelectedDevice() || !config.server.http[0]) return;
    pullInFlight = true;
    String url = String(config.server.http) + "/api/latest-data?device_id=" + String(runtimeSelectedDeviceId);
    String body;
    int code = 0;
    bool ok = httpGet(url, body, code);
    pullInFlight = false;
    if (!ok) {
        logLine(String("HTTP 拉取失败：") + url);
        return;
    }
    DynamicJsonDocument doc(8192);
    if (deserializeJson(doc, body) != DeserializationError::Ok) {
        logLine("latest-data 解析失败");
        return;
    }
    JsonArrayConst arr = doc["data"].as<JsonArrayConst>();
    if (arr.isNull()) return;
    for (JsonVariantConst envelope : arr) {
        const char *type = envelope["data_type"] | "";
        const char *deviceId = envelope["device_id"] | "";
        if (!deviceId[0]) continue;
        if (strcmp(type, "wifi") == 0) applyWifiEnvelope(deviceId, envelope["data"]);
        else if (strcmp(type, "bluetooth") == 0) applyBleEnvelope(deviceId, envelope["data"]);
    }
    lastLatestDataAt = millis();
    lastPullAt = millis();
    nextPollDeadline = millis() + kPollDeadlineMs;
}

void pollDeviceList() {
    if (!hasConfig() || WiFi.status() != WL_CONNECTED || !config.server.http[0]) return;
    String url = String(config.server.http) + "/api/devices?role=collector";
    String body;
    int code = 0;
    if (!httpGet(url, body, code)) return;
    DynamicJsonDocument doc(8192);
    if (deserializeJson(doc, body) != DeserializationError::Ok) return;
    JsonArrayConst arr = doc["devices"].as<JsonArrayConst>();
    if (arr.isNull()) return;
    char previousSelection[sizeof(runtimeSelectedDeviceId)]{};
    copyText(previousSelection, sizeof(previousSelection), String(runtimeSelectedDeviceId));
    deviceList.reset();
    for (JsonVariantConst item : arr) {
        String id = item["device_id"] | "";
        if (!id.length()) continue;
        deviceList.upsert(id.c_str(), item["name"] | id.c_str(), item["online"] | false);
    }
    deviceList.sortOnlineFirst();
    remoteDevicesDirty = true;
    lastDeviceListUpdate = millis();
    if (previousSelection[0]) {
        uint8_t index = 0;
        if (deviceList.find(previousSelection, index)) {
            copyText(runtimeSelectedDeviceId, sizeof(runtimeSelectedDeviceId), String(previousSelection));
            saveSelectedDevice();
            sendSubscribe(runtimeSelectedDeviceId);
        } else {
            runtimeSelectedDeviceId[0] = 0;
            saveSelectedDevice();
            beacon.stop();
            ble.stop();
        }
    }
}

String deviceListJson() {
    JsonDocument doc;
    doc["selected"] = runtimeSelectedDeviceId;
    JsonArray devices = doc["devices"].to<JsonArray>();
    for (uint8_t i = 0; i < deviceList.count(); ++i) {
        const RemoteDevice *source = deviceList.at(i);
        JsonObject item = devices.add<JsonObject>();
        item["id"] = source->deviceId;
        item["name"] = source->name;
        item["online"] = source->online;
        item["wifi"] = source->wifiCount;
        item["ble"] = source->bleCount;
    }
    String result;
    serializeJson(doc, result);
    return result;
}

void pullTick() {
    const uint32_t now = millis();
    if (!hasConfig() || WiFi.status() != WL_CONNECTED) return;
    const uint32_t pullIntervalMs = config.pullIntervalSec * 1000UL;
    if (now - lastSelectedPullAt >= pullIntervalMs) {
        // Each refresh replaces the complete simulation snapshot.
        beacon.stop();
        ble.stop();
        pollLatestSelected();
        lastSelectedPullAt = now;
    }
    // If the selected device went silent, fall back to polling /api/latest-data
    // instead of relying on push frames. This keeps Beacon and BLE in sync
    // with the latest server snapshot even when the Consumer socket lags.
    if (hasSelectedDevice() && nextPollDeadline && static_cast<int32_t>(millis() - nextPollDeadline) >= 0) {
        logLine("WebSocket 静默，重新拉取 latest-data");
        pollLatestSelected();
        lastSelectedPullAt = millis();
        nextPollDeadline = millis() + kPollDeadlineMs;
    }
}

void onWsEvent(WStype_t event, uint8_t *payload, size_t length) {
    if (event == WStype_CONNECTED) {
        authenticated = false;
        wsConnectedAt = millis();
        lastPingAt = millis();
        wsBackoffMs = kWsRetryStartMs;
        sendAuth();
        logLine("WebSocket 已连接，发送 Consumer 认证");
    } else if (event == WStype_DISCONNECTED) {
        authenticated = false;
        wsStarted = false;
        nextWsAt = millis() + wsBackoffMs;
        logLine(String("WebSocket 已断开，") + wsBackoffMs / 1000 + " 秒后重连");
        wsBackoffMs = min<uint32_t>(wsBackoffMs * 2, kWsRetryMaxMs);
    } else if (event == WStype_ERROR) logLine("WebSocket 库报告连接错误");
    else if (event == WStype_TEXT) {
        DynamicJsonDocument message(8192);
        if (deserializeJson(message, payload, length) != DeserializationError::Ok) {
            logLine(String("收到无效 JSON 长度=") + length);
            return;
        }
        const char *type = message["type"] | "";
        if (!strcmp(type, "auth_result")) {
            authenticated = message["success"] | false;
            if (authenticated) {
                wsBackoffMs = kWsRetryStartMs;
                logLine("Consumer 认证成功");
                if (hasSelectedDevice()) sendSubscribe(runtimeSelectedDeviceId);
            } else logLine("Consumer 认证失败");
        } else if (!strcmp(type, "device_list")) {
            applyDeviceList(message["devices"].as<JsonArrayConst>());
        } else if (!strcmp(type, "environment_data")) {
            const char *dataType = message["data_type"] | "";
            const char *deviceId = message["device_id"] | "";
            if (!deviceId[0]) return;
            if (!strcmp(dataType, "wifi")) applyWifiEnvelope(deviceId, message["data"]);
            else if (!strcmp(dataType, "bluetooth")) applyBleEnvelope(deviceId, message["data"]);
        } else if (!strcmp(type, "subscription_result")) {
            logLine(String("订阅结果：") + (message["device_id"] | "") + " types=" +
                    (const char *)(message["data_types"].as<JsonArrayConst>().isNull() ? "[]" : ""));
        } else if (!strcmp(type, "error")) {
            String code = message["code"] | "";
            String messageText = message["message"] | "";
            logLine(String("服务器错误：") + code + " " + messageText);
        } else if (!strcmp(type, "pong")) {
            // heartbeat reply
        } else if (!strcmp(type, "ping")) ws.sendTXT("{\"type\":\"ping\"}");
    }
}

void ledTask(void *) {
    LedMode previous = LedMode::Disconnected;
    bool ledOn = true;
    uint32_t changedAt = millis();
    for (;;) {
        const uint32_t now = millis();
        const LedMode mode = ledMode;
        if (mode != previous) {
            previous = mode;
            changedAt = now;
            ledOn = mode != LedMode::Normal;
            digitalWrite(kLedPin, ledOn ? LOW : HIGH);
        }
        if (mode == LedMode::Config) {
            ledOn = true;
            digitalWrite(kLedPin, LOW);
        } else if (mode == LedMode::Disconnected) {
            if (now - changedAt >= 200) {
                changedAt = now;
                ledOn = !ledOn;
                digitalWrite(kLedPin, ledOn ? LOW : HIGH);
            }
        } else if (now - changedAt >= (ledOn ? 100UL : 3000UL)) {
            changedAt = now;
            ledOn = !ledOn;
            digitalWrite(kLedPin, ledOn ? LOW : HIGH);
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

void ledMaintain() {
    ledMode = configMode
                               ? LedMode::Config
                               : (WiFi.status() != WL_CONNECTED || !ws.isConnected() || !authenticated)
                                     ? LedMode::Disconnected
                                     : LedMode::Normal;
}

void startConfigMode();

void buttonMaintain() {
    static bool last = HIGH;
    static uint32_t changed = 0;
    bool state = digitalRead(kBootPin);
    uint32_t now = millis();
    if (state != last) {
        last = state;
        changed = now;
        logLine(state == LOW ? "BOOT 按钮按下，GPIO9" : "BOOT 按钮释放，GPIO9");
    }
    if (state == LOW && now - changed >= 40) startConfigMode();
}

void sendLoginPage(const String &error = "") {
    String page;
    page.reserve(3000);
    page += F("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>RemoteEnv 管理登录</title><style>body{font-family:system-ui;background:#eef2f5;margin:0;padding:28px;color:#17202a}main{max-width:460px;margin:auto;background:#fff;padding:28px;border-radius:16px;box-shadow:0 8px 28px #0002}h1{margin-top:0}label{display:block;margin-top:18px;font-weight:600}input{box-sizing:border-box;width:100%;padding:12px;margin-top:7px;border:1px solid #bcc7d0;border-radius:8px;font-size:16px}button{width:100%;padding:12px;margin-top:24px;border:0;border-radius:8px;background:#1769aa;color:#fff;font-size:16px}.error{color:#b42318}</style></head><body><main><h1>RemoteEnv 管理登录</h1><p>登录后进入客户端配置面板。</p>");
    if (error.length()) {
        page += F("<p class='error'>");
        page += escapeHtml(error.c_str());
        page += F("</p>");
    }
    page += F("<form method='post' action='/login'><label>管理员密码<input name='password' type='password' required autofocus></label><button type='submit'>登录并进入配置</button></form></main></body></html>");
    headers();
    web.send(200, "text/html; charset=utf-8", page);
}

void setupPasswordPage() {
    String page = "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>首次配置</title><style>body{font-family:system-ui;background:#eef2f5;margin:0;padding:28px}main{max-width:540px;margin:auto;background:#fff;padding:28px;border-radius:16px;box-shadow:0 8px 28px #0002}label{display:block;margin-top:16px;font-weight:600}input{box-sizing:border-box;width:100%;padding:12px;margin-top:6px;border:1px solid #bcc7d0;border-radius:8px}button{width:100%;padding:12px;margin-top:24px;border:0;border-radius:8px;background:#1769aa;color:#fff}</style></head><body><main><h1>首次配置管理员密码</h1><p><b>必须先设置管理员密码。</b></p><p>管理员密码用于保护 WiFi、服务器地址和 Consumer Token。设置成功后才能继续配置客户端。</p><form method='post' action='/setup-password'><label>管理员密码<input name='password' type='password' minlength='8' maxlength='96' required autofocus></label><label>确认管理员密码<input name='confirm' type='password' minlength='8' maxlength='96' required></label><button type='submit'>设置密码并继续</button></form></main></body></html>";
    headers();
    web.send(200, "text/html; charset=utf-8", page);
}

void configPage() {
    touchConfig();
    if (!hasPassword()) {
        setupPasswordPage();
        return;
    }
    if (!requireLogin()) return;
    String page;
    page.reserve(15000);
    page += F("<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>RemoteEnv 客户端配置</title><style>:root{color-scheme:light}*{box-sizing:border-box}body{font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:linear-gradient(135deg,#eaf2f8,#f7f9fb);margin:0;padding:24px;color:#17202a}main{max-width:860px;margin:auto}.hero,.card{background:rgba(255,255,255,.92);border:1px solid #dbe5ec;border-radius:18px;box-shadow:0 10px 30px #1c34420f}.hero{padding:28px;margin-bottom:18px}.hero h1{margin:0 0 8px;font-size:28px}.hero p{margin:0;color:#607080}.card{padding:22px;margin-bottom:18px}.card h2{margin:0 0 6px;font-size:20px}.card>p{margin:0 0 16px;color:#607080}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:14px}fieldset{border:1px solid #d8e2e9;border-radius:12px;padding:14px;margin:0}legend{padding:0 6px;font-weight:700;color:#1769aa}label{display:block;margin-top:10px;font-weight:600;color:#334454}input{width:100%;padding:11px;margin-top:5px;border:1px solid #b9c7d1;border-radius:9px;font-size:15px;background:#fff}input:focus{outline:2px solid #b6d9f3;border-color:#1769aa}button{padding:12px 18px;border:0;border-radius:9px;background:#1769aa;color:white;font-size:15px;cursor:pointer}.secondary{background:#64727d}.actions,.wifi-tabs,.pagination{display:flex;gap:10px;flex-wrap:wrap;margin-top:16px}.wifi-tab{border-radius:999px;padding:8px 15px;background:#dfe7ed;color:#334454}.wifi-tab.active{background:#1769aa;color:#fff}.wifi-editor{display:none;margin-top:14px}.wifi-editor.active{display:block}.device-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px;margin-top:14px}.device{display:block;border:1px solid #d8e2e9;border-radius:13px;padding:14px;background:#fff;cursor:pointer}.device.selected{border:2px solid #1769aa;background:#eef6fc}.device input{width:auto;margin:0 8px 0 0}.device-name{font-weight:700}.device-meta{display:block;margin:6px 0;color:#607080;font-size:12px;overflow-wrap:anywhere}.pill{display:inline-block;padding:3px 9px;border-radius:999px;font-size:12px;background:#e1e5ea}.online{background:#d3f3df;color:#086c2a}.tag{font-size:12px;background:#eef6fc;color:#1769aa;border-radius:6px;padding:2px 7px}.actions{margin-top:20px}a{color:#1769aa;text-decoration:none}.notice{background:#fff7df;border:1px solid #f1d58b;color:#765500;border-radius:10px;padding:13px;margin-top:14px}.muted{font-size:13px;color:#71808d}</style></head><body><main><section class='hero'><h1>RemoteEnv 客户端配置</h1><p>ESP32-C3 环境模拟客户端 · Consumer 模式 · 自定义周期拉取并模拟</p><div class='notice'>配网模式在连续 5 分钟没有任何网页操作后会自动重启并退出配置模式。客户端只保存当前选中的模拟设备。</div></section><form method='post' action='/save'><section class='card'><h2>WiFi 网络列表</h2><p>点击胶囊配置对应网络；设备按照 WiFi 1-5 的顺序尝试连接。</p><div class='wifi-tabs'>");
    for (uint8_t i = 0; i < kMaxWifi; ++i) {
        page += F("<button type='button' class='wifi-tab");
        if (i == 0) page += F(" active");
        page += F("' onclick='showWifi("); page += i; page += F(")'>WiFi "); page += i + 1; page += F("</button>");
    }
    page += F("</div>");
    for (uint8_t i = 0; i < kMaxWifi; ++i) {
        page += F("<fieldset class='wifi-editor");
        if (i == 0) page += F(" active");
        page += F("'><legend>WiFi ");
        page += i + 1;
        page += F("</legend><label>SSID<input name='ssid");
        page += i;
        page += F("' maxlength='63' value='");
        page += escapeHtml(config.wifi[i].ssid).c_str();
        page += F("' placeholder='例如 RemoteEnv-WiFi'></label><label>密码<input name='password");
        page += i;
        page += F("' type='password' maxlength='63' value='");
        page += escapeHtml(config.wifi[i].password).c_str();
        page += F("'></label></fieldset>");
    }
    page += F("</section><section class='card'><h2>服务器连接</h2><p>单服务器长期连接，客户端通过 Consumer 角色订阅远程采集器数据。</p><label>WebSocket 地址<input name='ws' maxlength='159' required value='");
    page += escapeHtml(config.server.ws).c_str();
    page += F("' placeholder='wss://example.invalid/ws'></label><label>Consumer Token<input name='token' maxlength='159' required value='");
    page += escapeHtml(config.server.token).c_str();
    page += F("'></label><label>拉取间隔（秒）<input name='pullInterval' type='number' min='1' max='3600' required value='");
    page += config.pullIntervalSec;
    page += F("'></label><p class='muted'>每轮先停止旧广播，拉取最新数据，再从第 1 条开始以 25ms 间隔循环发送 WiFi Beacon 和蓝牙广播。</p><div class='actions'><button id='loadSources' type='button' onclick='loadSources(true)'>立即加载数据源</button><span id='sourceStatus' class='muted'></span></div>");
    page += F("<h3>数据源设备</h3><div id='sourceList'>");
    uint8_t total = deviceList.count();
    int requestedPage = web.hasArg("p") ? web.arg("p").toInt() : 0;
    const uint8_t perPage = 5;
    uint8_t pages = total ? (total + perPage - 1) / perPage : 1;
    uint8_t currentPage = constrain(requestedPage, 0, pages - 1);
    if (!total) page += F("<p class='muted'>点击“立即加载数据源”获取服务端设备列表。</p>");
    else {
        page += F("<div class='device-grid'>");
        uint8_t end = min<uint8_t>((currentPage + 1) * perPage, total);
        for (uint8_t i = currentPage * perPage; i < end; ++i) {
            const RemoteDevice *d = deviceList.at(i);
            bool selected = hasSelectedDevice() && strcmp(runtimeSelectedDeviceId, d->deviceId) == 0;
            page += F("<label class='device"); if (selected) page += F(" selected");
            page += F("'><input type='radio' name='sourceDevice' value='");
            page += escapeHtml(d->deviceId); page += F("'"); if (selected) page += F(" checked");
            page += F(" onchange='selectSource(this.value)'><span class='device-name'>");
            page += escapeHtml(d->name); page += F("</span><span class='device-meta'>");
            page += escapeHtml(d->deviceId); page += F("</span><span class='pill ");
            if (d->online) page += F("online"); page += F("'>"); page += d->online ? F("在线") : F("离线");
            page += F("</span> <span class='tag'>WiFi "); page += d->wifiCount;
            page += F("</span> <span class='tag'>BLE "); page += d->bleCount; page += F("</span></label>");
        }
        page += F("</div><div class='pagination'>");
        if (currentPage > 0) { page += F("<a href='/?p="); page += currentPage - 1; page += F("'>上一页</a>"); }
        page += F("<span class='muted'>第 "); page += currentPage + 1; page += F(" / "); page += pages; page += F(" 页</span>");
        if (currentPage + 1 < pages) { page += F("<a href='/?p="); page += currentPage + 1; page += F("'>下一页</a>"); }
        page += F("</div>");
    }
    page += F("</div></section><section class='card'><h2>安全设置</h2><p>管理员密码不会以明文显示或上传。</p><div class='grid'><label>新管理员密码（可选）<input name='newPassword' type='password' minlength='8' maxlength='96' placeholder='留空表示不修改'></label><label>确认新管理员密码<input name='confirmPassword' type='password' minlength='8' maxlength='96' placeholder='再次输入新密码'></label></div><div class='actions'><button type='submit'>保存配置并重启</button><a href='/panel'><button type='button' class='secondary'>运行面板</button></a><button type='submit' formaction='/logout' class='secondary'>退出登录</button></div></section></form><script>let sourceData=[],sourcePage=0;const esc=s=>String(s==null?'':s).replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));function showWifi(n){document.querySelectorAll('.wifi-tab,.wifi-editor').forEach((e,i)=>e.classList.toggle('active',i%5===n))}function renderSources(selected){const box=document.getElementById('sourceList'),pages=Math.max(1,Math.ceil(sourceData.length/5));sourcePage=Math.min(sourcePage,pages-1);const items=sourceData.slice(sourcePage*5,sourcePage*5+5);box.innerHTML=items.length?\"<div class='device-grid'>\"+items.map(d=>\"<label class='device \"+(d.id===selected?'selected':'')+\"'><input type='radio' name='sourceDevice' value='\"+esc(d.id)+\"' \"+(d.id===selected?'checked':'')+\" onchange='selectSource(this.value)'><span class='device-name'>\"+esc(d.name)+\"</span><span class='device-meta'>\"+esc(d.id)+\"</span><span class='pill \"+(d.online?'online':'')+\"'>\"+(d.online?'在线':'离线')+\"</span> <span class='tag'>WiFi \"+d.wifi+\"</span> <span class='tag'>BLE \"+d.ble+\"</span></label>\").join('')+\"</div><div class='pagination'><button type='button' class='secondary' onclick='changeSourcePage(-1)' \"+(sourcePage?'':'disabled')+\">上一页</button><span class='muted'>第 \"+(sourcePage+1)+\" / \"+pages+\" 页</span><button type='button' onclick='changeSourcePage(1)' \"+(sourcePage+1<pages?'':'disabled')+\">下一页</button></div>\":\"<p class='muted'>服务端当前没有可见的数据源设备。</p>\";box.dataset.selected=selected||''}function changeSourcePage(step){sourcePage+=step;renderSources(document.getElementById('sourceList').dataset.selected)}async function api(url,opt){const r=await fetch(url,opt);if(r.status===401){location.href='/login';throw Error('login_required')}if(!r.ok)throw Error(await r.text());return r.json()}async function loadSources(refresh){const b=document.getElementById('loadSources'),s=document.getElementById('sourceStatus');b.disabled=true;s.textContent='正在拉取…';try{const d=await api(refresh?'/api/devices/refresh':'/api/devices',{method:refresh?'POST':'GET'});sourceData=d.devices||[];sourcePage=0;renderSources(d.selected);s.textContent='已加载 '+sourceData.length+' 个设备'}catch(e){if(e.message!=='login_required')s.textContent='加载失败：'+e.message}finally{b.disabled=false}}async function selectSource(v){const s=document.getElementById('sourceStatus');s.textContent='正在切换…';try{const d=await api('/api/select',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'device='+encodeURIComponent(v)});renderSources(d.selected);s.textContent='已选中，正在拉取模拟数据'}catch(e){if(e.message!=='login_required')s.textContent='切换失败：'+e.message}}loadSources(false);setInterval(()=>api('/api/session').catch(()=>{}),60000);</script></main></body></html>");
    headers();
    web.send(200, "text/html; charset=utf-8", page);
}

String renderSelectedSnapshot() {
    String s;
    s.reserve(2048);
    s += F("<section class='card'><h2>当前模拟设备</h2>");
    if (!hasSelectedDevice()) {
        s += F("<p class='muted'>尚未选择任何远程采集器。请到「数据源管理」中点击「立即模拟」开始模拟。</p>");
    } else {
        s += F("<p>设备 ID：<b>");
        s += escapeHtml(runtimeSelectedDeviceId).c_str();
        s += F("</b></p><p>WiFi Beacon：");
        s += beacon.running() ? F("运行中 ") : F("未运行 ");
        s += F(" · BLE 广播：");
        s += ble.running() ? F("运行中") : F("未运行");
        s += F(" · 信道：");
        s += beacon.currentChannel();
        s += F("</p>");
        s += F("<h3>WiFi 列表（最近一次）</h3><pre class='log'>");
        if (lastSelectedWifiJson[0]) s += escapeHtml(lastSelectedWifiJson).c_str();
        else s += F("[]");
        s += F("</pre><h3>BLE 设备（最近一次）</h3><pre class='log'>");
        if (lastSelectedBleJson[0]) s += escapeHtml(lastSelectedBleJson).c_str();
        else s += F("[]");
        s += F("</pre>");
    }
    s += F("</section>");
    return s;
}

void devicesPage() {
    touchConfig();
    if (!hasPassword()) {
        setupPasswordPage();
        return;
    }
    if (!requireLogin()) return;
    int pageParam = 0;
    if (web.hasArg("p")) pageParam = web.arg("p").toInt();
    if (pageParam < 0) pageParam = 0;
    String page;
    page.reserve(16000);
    page += F("<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><meta http-equiv='refresh' content='5'><title>RemoteEnv 数据源管理</title><style>:root{color-scheme:light}*{box-sizing:border-box}body{font-family:system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:linear-gradient(135deg,#eaf2f8,#f7f9fb);margin:0;padding:24px;color:#17202a}main{max-width:880px;margin:auto}.hero,.card{background:rgba(255,255,255,.92);border:1px solid #dbe5ec;border-radius:18px;box-shadow:0 10px 30px #1c34420f}.hero{padding:24px;margin-bottom:18px}.hero h1{margin:0;font-size:24px}.hero p{margin:6px 0 0;color:#607080}.card{padding:22px;margin-bottom:18px}.card h2{margin:0 0 6px;font-size:20px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}.device{border:1px solid #d8e2e9;border-radius:14px;padding:16px;background:#fff;display:flex;flex-direction:column;gap:6px}.device.selected{border:2px solid #1769aa;background:#eef6fc}.device .name{font-weight:700;font-size:16px;color:#17202a}.device .meta{font-size:13px;color:#5d6872}.device .status{font-size:13px}.device form{margin-top:auto}button{padding:9px 14px;border:0;border-radius:8px;background:#1769aa;color:#fff;font-size:14px;cursor:pointer}.secondary{background:#64727d}.pagination{display:flex;justify-content:space-between;align-items:center;margin-top:18px;gap:10px;flex-wrap:wrap}.pagination form{display:inline}.empty{color:#5d6872}a{color:#1769aa;text-decoration:none}.muted{color:#5d6872;font-size:13px}.log{white-space:pre-wrap;background:#101820;color:#d8f3dc;padding:14px;border-radius:10px;font-size:12px;line-height:1.5;max-height:340px;overflow:auto}select{padding:9px;border-radius:8px;border:1px solid #b9c7d1;font-size:14px}.pill{display:inline-block;padding:3px 9px;border-radius:999px;font-size:12px}.online{background:#d3f3df;color:#086c2a}.offline{background:#e1e5ea;color:#5d6872}.tag{font-size:12px;background:#eef6fc;color:#1769aa;border-radius:6px;padding:2px 7px}</style></head><body><main><section class='hero'><h1>远程数据源管理</h1><p>在线采集器优先显示 · 每页 5 个 · 立即模拟会同步更新 Beacon 和 BLE 广播</p></section>");
    page += renderSelectedSnapshot();
    page += F("<section class='card'><h2>采集器列表</h2>");
    uint8_t total = deviceList.count();
    if (total == 0) {
        page += F("<p class='empty'>当前没有可见的采集器。请确认 WebSocket 已认证，且服务端存在 collector 记录。</p>");
    } else {
        uint8_t onlineCount = 0;
        for (uint8_t i = 0; i < total; ++i) if (deviceList.at(i)->online) ++onlineCount;
        page += F("<p class='muted'>总数：");
        page += total;
        page += F(" · 在线：");
        page += onlineCount;
        page += F(" · 离线：");
        page += total - onlineCount;
        page += F("</p>");
        const uint8_t perPage = 5;
        const uint8_t pages = (total + perPage - 1) / perPage;
        uint8_t currentPage = (uint8_t)pageParam;
        if (currentPage >= pages) currentPage = pages - 1;
        const uint8_t start = currentPage * perPage;
        const uint8_t end = min<uint8_t>(start + perPage, total);
        page += F("<div class='grid'>");
        for (uint8_t i = start; i < end; ++i) {
            const RemoteDevice *d = deviceList.at(i);
            page += d->online ? F("<div class='device'>") : F("<div class='device'>");
            if (hasSelectedDevice() && strcmp(runtimeSelectedDeviceId, d->deviceId) == 0) page += F("<div class='device selected'>");
            else page += F("<div class='device'>");
            page += F("<div class='name'>");
            page += escapeHtml(d->name).c_str();
            page += F("</div><div class='meta'>");
            page += escapeHtml(d->deviceId).c_str();
            page += F("</div><div class='status'>");
            page += d->online ? F("<span class='pill online'>在线</span>") : F("<span class='pill offline'>离线</span>");
            page += F(" <span class='tag'>WiFi ");
            page += d->wifiCount;
            page += F("</span> <span class='tag'>BLE ");
            page += d->bleCount;
            page += F("</span></div>");
            page += F("<form method='post' action='/select'><input type='hidden' name='device' value='");
            page += escapeHtml(d->deviceId).c_str();
            page += F("'><button type='submit'>立即模拟</button></form></div>");
        }
        page += F("</div>");
        if (pages > 1) {
            page += F("<div class='pagination'><form method='get'><input type='hidden' name='p' value='");
            page += (int)currentPage - 1 < 0 ? 0 : currentPage - 1;
            page += F("'><button class='secondary' type='submit'>上一页</button></form><div class='muted'>第 ");
            page += currentPage + 1;
            page += F(" / ");
            page += pages;
            page += F(" 页</div><form method='get'><input type='hidden' name='p' value='");
            page += currentPage + 1 < pages ? currentPage + 1 : pages - 1;
            page += F("'><button type='submit'>下一页</button></form></div>");
        }
    }
    page += F("</section><p><a href='/'>配置页</a> · <a href='/panel'>运行面板</a></p></main></body></html>");
    headers();
    web.send(200, "text/html; charset=utf-8", page);
}

void panelPage() {
    if (!requireLogin()) return;
    String page;
    page.reserve(5000);
    page += F("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><meta http-equiv='refresh' content='5'><title>RemoteEnv 客户端面板</title><style>body{font-family:system-ui;background:#eef2f5;margin:0;padding:24px}main{max-width:760px;margin:auto;background:#fff;padding:26px;border-radius:16px;box-shadow:0 8px 28px #0002}pre{white-space:pre-wrap;background:#101820;color:#d8f3dc;padding:16px;border-radius:10px;min-height:220px}a{color:#1769aa}</style></head><body><main><h1>ESP32-C3 客户端面板</h1><p>WiFi：");
    page += WiFi.status() == WL_CONNECTED ? F("已连接 ") : F("未连接 ");
    page += WiFi.localIP().toString();
    page += F("<br>WebSocket：");
    page += authenticated && ws.isConnected() ? F("已认证") : F("未连接或未认证");
    page += F("<br>Consumer Token：");
    page += escapeHtml(config.server.token).c_str();
    page += F("<br>当前模拟设备：");
    page += hasSelectedDevice() ? String(escapeHtml(runtimeSelectedDeviceId)) : String("未选择");
    page += F("<br>WiFi Beacon：");
    page += beacon.running() ? F("运行中") : F("未运行");
    page += F(" · BLE 广播：");
    page += ble.running() ? F("运行中") : F("未运行");
    page += F("<br>BOOT 按钮：GPIO9　板载蓝灯：GPIO8（LOW=亮，HIGH=灭）</p><h2>最近日志</h2><pre>");
    for (uint8_t i = 0; i < logCount; ++i) {
        page += escapeHtml(logs[i]).c_str();
        page += '\n';
    }
    page += F("</pre><p><a href='/'>返回配置面板</a></p></main></body></html>");
    headers();
    web.send(200, "text/html; charset=utf-8", page);
}

void handleLogin() {
    if (!hasPassword()) {
        web.sendHeader("Location", "/setup-password", true);
        web.send(302, "text/plain", "请先设置管理员密码");
        return;
    }
    if (!web.hasArg("password") || !constantEquals(config.passwordHash, passwordHash(web.arg("password")))) {
        sendLoginPage("管理员密码错误");
        return;
    }
    createSession();
    headers();
    web.sendHeader("Set-Cookie", String("REMOTENV_SESSION=") + session + "; Max-Age=1800; HttpOnly; SameSite=Strict; Path=/", true);
    web.sendHeader("Location", "/", true);
    web.send(302, "text/plain", "登录成功");
}

void handleSetupPasswordPost() {
    if (hasPassword()) {
        if (!requireLogin()) return;
        web.send(409, "text/plain", "管理员密码已经设置");
        return;
    }
    String password = web.arg("password");
    if (password.length() < 8 || password.length() > 96 || password != web.arg("confirm")) {
        setupPasswordPage();
        return;
    }
    copyText(config.passwordHash, sizeof(config.passwordHash), passwordHash(password));
    saveConfig();
    createSession();
    headers();
    web.sendHeader("Set-Cookie", String("REMOTENV_SESSION=") + session + "; Max-Age=1800; HttpOnly; SameSite=Strict; Path=/", true);
    web.sendHeader("Location", "/", true);
    web.send(302, "text/plain", "密码已设置");
}

void handleLogout() {
    session = "";
    headers();
    web.sendHeader("Set-Cookie", "REMOTENV_SESSION=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/", true);
    web.sendHeader("Location", "/login", true);
    web.send(302, "text/plain", "已退出");
}

void handleSelectDevice() {
    touchConfig();
    if (!requireLogin() || !web.hasArg("device")) return;
    String deviceId = web.arg("device");
    if (deviceId.length() == 0 || deviceId.length() >= sizeof(runtimeSelectedDeviceId)) {
        web.send(400, "text/plain; charset=utf-8", "设备 ID 无效");
        return;
    }
    copyText(runtimeSelectedDeviceId, sizeof(runtimeSelectedDeviceId), deviceId);
    saveSelectedDevice();
    beacon.stop();
    ble.stop();
    lastSelectedWifiJson[0] = 0;
    lastSelectedBleJson[0] = 0;
    lastPullAt = 0;
    if (authenticated && ws.isConnected()) sendSubscribe(runtimeSelectedDeviceId, true);
    pullTick();
    web.sendHeader("Location", "/", true);
    web.send(303, "text/plain; charset=utf-8", "设备已选择，等待数据");
}

void handleClearSelected() {
    touchConfig();
    if (!requireLogin()) return;
    runtimeSelectedDeviceId[0] = 0;
    saveSelectedDevice();
    beacon.stop();
    ble.stop();
    web.sendHeader("Location", "/", true);
    web.send(303, "text/plain; charset=utf-8", "已停止模拟");
}

void handleApiSelectDevice() {
    touchConfig();
    if (!requireApiLogin()) return;
    String deviceId = web.arg("device");
    if (!deviceId.length() || deviceId.length() >= sizeof(runtimeSelectedDeviceId)) {
        web.send(400, "application/json; charset=utf-8", "{\"error\":\"invalid_device\"}");
        return;
    }
    copyText(runtimeSelectedDeviceId, sizeof(runtimeSelectedDeviceId), deviceId);
    saveSelectedDevice();
    beacon.stop();
    ble.stop();
    lastSelectedWifiJson[0] = 0;
    lastSelectedBleJson[0] = 0;
    lastSelectedPullAt = 0;
    if (authenticated && ws.isConnected()) sendSubscribe(runtimeSelectedDeviceId, true);
    headers();
    web.send(200, "application/json; charset=utf-8", deviceListJson());
}

void handleSave() {
    touchConfig();
    if (!requireLogin()) return;
    Config next = config;
    uint8_t n = 0;
    for (uint8_t i = 0; i < kMaxWifi; ++i) {
        String ssid = web.arg(String("ssid") + i);
        if (!ssid.length()) continue;
        copyText(next.wifi[n].ssid, sizeof(next.wifi[n].ssid), ssid);
        copyText(next.wifi[n].password, sizeof(next.wifi[n].password), web.arg(String("password") + i));
        ++n;
    }
    String host, path;
    uint16_t port;
    bool secure;
    String wsUrl = web.arg("ws");
    if (!n || !parseWs(wsUrl.c_str(), host, port, path, secure) || !web.arg("token").length()) {
        web.send(400, "text/plain; charset=utf-8", "至少配置一个 WiFi，且 WebSocket 地址、Token 必须完整");
        return;
    }
    copyText(next.server.ws, sizeof(next.server.ws), wsUrl);
    copyText(next.server.token, sizeof(next.server.token), web.arg("token"));
    uint32_t intervalSec = web.arg("pullInterval").toInt();
    if (intervalSec < kMinPullIntervalSec || intervalSec > kMaxPullIntervalSec) {
        web.send(400, "text/plain; charset=utf-8", "拉取间隔必须为 1-3600 秒");
        return;
    }
    next.pullIntervalSec = intervalSec;
    const String newPassword = web.arg("newPassword");
    if (newPassword.length() > 0) {
        if (newPassword.length() < 8 || newPassword.length() > 96 || newPassword != web.arg("confirmPassword")) {
            web.send(400, "text/plain; charset=utf-8", "新管理员密码无效或两次输入不一致");
            return;
        }
        copyText(next.passwordHash, sizeof(next.passwordHash), passwordHash(newPassword));
    }
    config = next;
    deriveHttpFromWs();
    saveConfig();
    session = "";
    headers();
    web.send(200, "text/html; charset=utf-8", "<meta charset='utf-8'><p>配置已保存，设备将在短暂延迟后重启。</p>");
    delay(500);
    ESP.restart();
}

void registerRoutes() {
    if (webRoutesRegistered) return;
    webRoutesRegistered = true;
    const char *keys[] = {"Cookie"};
    web.collectHeaders(keys, 1);
    web.on("/", HTTP_GET, configPage);
    web.on("/login", HTTP_GET, []() { sendLoginPage(); });
    web.on("/login", HTTP_POST, handleLogin);
    web.on("/setup-password", HTTP_GET, setupPasswordPage);
    web.on("/setup-password", HTTP_POST, handleSetupPasswordPost);
    web.on("/logout", HTTP_POST, handleLogout);
    web.on("/panel", HTTP_GET, panelPage);
    web.on("/save", HTTP_POST, handleSave);
    web.on("/select", HTTP_POST, handleSelectDevice);
    web.on("/clear", HTTP_POST, handleClearSelected);
    web.on("/api/devices", HTTP_GET, []() {
        touchConfig();
        if (!requireApiLogin()) return;
        headers();
        web.send(200, "application/json; charset=utf-8", deviceListJson());
    });
    web.on("/api/session", HTTP_GET, []() {
        touchConfig();
        if (!requireApiLogin()) return;
        headers();
        web.send(200, "application/json; charset=utf-8", "{\"ok\":true}");
    });
    web.on("/api/devices/refresh", HTTP_POST, []() {
        touchConfig();
        if (!requireApiLogin()) return;
        pollDeviceList();
        headers();
        web.send(200, "application/json; charset=utf-8", deviceListJson());
    });
    web.on("/api/select", HTTP_POST, handleApiSelectDevice);
    web.onNotFound([]() { web.send(404, "text/plain", "Not found"); });
}

void startLocalWebServer() {
    registerRoutes();
    if (!webServerStarted) {
        web.begin();
        webServerStarted = true;
    }
}

void startConfigMode() {
    if (configMode) return;
    configMode = true;
    configStartedAt = millis();
    lastConfigActivityAt = configStartedAt;
    authenticated = false;
    ws.disconnect();
    wsStarted = false;
    digitalWrite(kLedPin, LOW);
    WiFi.disconnect(true);
    WiFi.mode(WIFI_AP);
    String name = String("RemoteEnv-Client-") + chipId();
    WiFi.softAP(name.c_str(), kApPassword);
    registerRoutes();
    if (!webServerStarted) {
        web.begin();
        webServerStarted = true;
    }
    logLine(String("配置 AP：") + name + "，访问 http://" + WiFi.softAPIP().toString() + "/");
}

void beginWifi() {
    WiFi.mode(WIFI_STA);
    WiFi.begin(config.wifi[wifiIndex].ssid, config.wifi[wifiIndex].password);
    wifiAttemptAt = millis();
    wifiConnecting = true;
    logLine(String("尝试连接 WiFi ") + (wifiIndex + 1) + "：" + config.wifi[wifiIndex].ssid);
}

void maintainWifi() {
    uint32_t now = millis();
    if (WiFi.status() == WL_CONNECTED) {
        if (wifiConnecting) {
            wifiConnecting = false;
            wifiBackoffMs = kWifiBackoffStartMs;
            wifiIndex = 0;
            wifiRound = 0;
            nextWsAt = now;
            logLine(String("WiFi 已连接：") + WiFi.localIP().toString());
            setenv("TZ", "CST-8", 1);
            tzset();
            configTime(0, 0, "ntp1.aliyun.com", "pool.ntp.org", "time.nist.gov");
            if (!webServerStarted) {
                registerRoutes();
                web.begin();
                webServerStarted = true;
            }
        }
        return;
    }
    authenticated = false;
    if (wsStarted) {
        ws.disconnect();
        wsStarted = false;
    }
    if (wifiConnecting && now - wifiAttemptAt < kWifiAttemptMs) return;
    if (wifiConnecting) {
        wifiConnecting = false;
        WiFi.disconnect();
        ++wifiIndex;
        if (wifiIndex >= wifiCount()) {
            wifiIndex = 0;
            ++wifiRound;
            nextWifiAt = now + wifiBackoffMs;
            logLine(String("WiFi 第 ") + wifiRound + " 轮失败，" + wifiBackoffMs / 1000 + " 秒后重试");
            wifiBackoffMs = min<uint32_t>(wifiBackoffMs * 2, kWifiBackoffMaxMs);
        } else nextWifiAt = now + 250;
    }
    if (static_cast<int32_t>(now - nextWifiAt) >= 0) {
        nextWifiAt = UINT32_MAX;
        beginWifi();
    }
}

void maintainWs() {
    uint32_t now = millis();
    if (ws.isConnected() && !authenticated && wsConnectedAt && now - wsConnectedAt >= kAuthTimeoutMs) {
        logLine("WebSocket 认证超时，主动断开");
        ws.disconnect();
        wsStarted = false;
        nextWsAt = now + wsBackoffMs;
    }
    if (!wsStarted && static_cast<int32_t>(now - nextWsAt) >= 0) {
        String host, path;
        uint16_t port;
        bool secure;
        if (parseWs(config.server.ws, host, port, path, secure)) {
            if (secure) ws.beginSSL(host.c_str(), port, path.c_str(), nullptr, "arduino");
            else ws.begin(host.c_str(), port, path.c_str(), "arduino");
            ws.onEvent(onWsEvent);
            ws.setReconnectInterval(wsBackoffMs);
            ws.enableHeartbeat(30000, 5000, 2);
            wsStarted = true;
            logLine("开始 WebSocket 稳定重连");
        } else nextWsAt = now + wsBackoffMs;
    }
    if (authenticated && ws.isConnected() && now - lastPingAt >= kPingIntervalMs) {
        ws.sendTXT("{\"type\":\"ping\"}");
        lastPingAt = now;
    }
}
}

void setup() {
    Serial.begin(115200);
    delay(100);
    Serial.println("RemoteEnv ESP32-C3 client boot");
    pinMode(kLedPin, OUTPUT);
    digitalWrite(kLedPin, LOW);
    xTaskCreate(ledTask, "status-led", 2048, nullptr, 1, nullptr);
    pinMode(kBootPin, INPUT_PULLUP);
    Serial.println("BOOT button: GPIO9");
    Serial.println("LED GPIO8 active-low: LOW=ON HIGH=OFF");
    NimBLEDevice::init("");
    loadConfig();
    beacon.begin();
    ble.begin();
    pull.begin(config.server.http, config.server.token, config.pullIntervalSec * 1000UL);
    if (!hasConfig() || digitalRead(kBootPin) == LOW) {
        startConfigMode();
        return;
    }
    beginWifi();
    startLocalWebServer();
}

void loop() {
    ledMaintain();
    buttonMaintain();
    if (configMode) {
        web.handleClient();
        if (millis() - lastConfigActivityAt >= kConfigTimeoutMs) {
            logLine("配网模式五分钟无操作，重启进入正常模式");
            delay(100);
            ESP.restart();
        }
        delay(2);
        return;
    }
    web.handleClient();
    maintainWifi();
    if (WiFi.status() == WL_CONNECTED) {
        ws.loop();
        maintainWs();
        pullTick();
        beacon.loop();
        ble.loop();
    }
    ledMaintain();
    delay(2);
}
