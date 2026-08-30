#include <Arduino.h>
#include <ArduinoJson.h>
#include <mbedtls/sha256.h>
#include <Preferences.h>
#include <WebServer.h>
#include <NimBLEDevice.h>
#include <WiFi.h>
#include <WebSocketsClient.h>
#include <sys/time.h>
#include <time.h>

namespace {
constexpr uint8_t kLedPin = 8;
constexpr uint8_t kConfigButtonPin = 9; // BOOT button
constexpr uint8_t kMaxWifiNetworks = 5;
constexpr size_t kPasswordHashLength = 64;
constexpr size_t kSessionTokenLength = 32;
constexpr uint32_t kSessionTimeoutMs = 1800000;
constexpr uint32_t kDefaultUploadIntervalSeconds = 15;
constexpr uint32_t kMinimumUploadIntervalSeconds = 10;
constexpr uint32_t kMaximumUploadIntervalSeconds = 30;
constexpr uint32_t kWifiConnectTimeoutMs = 15000;
constexpr uint32_t kWifiRetryBaseIntervalMs = 5000;
constexpr uint32_t kWifiRetryMaximumIntervalMs = 60000;
constexpr uint32_t kWebSocketRetryBaseIntervalMs = 10000;
constexpr uint32_t kWebSocketRetryMaximumIntervalMs = 60000;
constexpr uint32_t kAuthTimeoutMs = 20000;
constexpr uint32_t kApplicationPingIntervalMs = 20000;
constexpr uint32_t kConfigModeTimeoutMs = 300000;
constexpr uint8_t kLogCapacity = 20;
constexpr uint8_t kLogLineLength = 96;
constexpr size_t kWifiSnapshotBufferSize = 8192;
constexpr size_t kBluetoothSnapshotBufferSize = 12288;
constexpr time_t kMinimumValidEpoch = 1700000000;
constexpr char kApPassword[] = "12345678";
constexpr char kBluetoothDataType[] = "bluetooth";
constexpr char kWifiDataType[] = "wifi";
constexpr uint32_t kConfigMagic = 0x52454337;
constexpr uint32_t kPreviousConfigMagic = 0x52454336;
constexpr uint32_t kOlderConfigMagic = 0x52454335;

struct WifiConfig { char ssid[64]; char password[64]; };
struct ServerConfig { char wsUrl[160]; char token[160]; char deviceId[64]; };
struct DeviceConfig { WifiConfig wifi[kMaxWifiNetworks]; ServerConfig server; char passwordHash[65]; uint32_t uploadIntervalSeconds; };
struct StoredConfig { uint32_t magic; DeviceConfig config; };
struct LegacyDeviceConfig { char wifiSsid[64]; char wifiPassword[64]; char wsUrl[160]; char token[160]; char deviceId[64]; char passwordHash[65]; uint32_t uploadIntervalSeconds; };
struct LegacyStoredConfig { uint32_t magic; LegacyDeviceConfig config; };
struct PreviousServerConfig { char wsUrl[160]; char token[160]; };
struct PreviousDeviceConfig { WifiConfig wifi[kMaxWifiNetworks]; PreviousServerConfig servers[3]; char deviceId[64]; char passwordHash[65]; uint32_t uploadIntervalSeconds; };
struct PreviousStoredConfig { uint32_t magic; PreviousDeviceConfig config; };

DeviceConfig config;
WebSocketsClient websocket;
WebServer webServer(80);
Preferences sequencePreferences;
uint32_t uploadIntervalSeconds = kDefaultUploadIntervalSeconds;
uint32_t wifiAttemptStartedAt = 0;
uint32_t nextWifiRetryAt = 0;
uint32_t wifiRetryDelayMs = kWifiRetryBaseIntervalMs;
uint8_t wifiIndex = 0;
uint8_t wifiRound = 0;
bool wifiConnecting = false;
bool authenticated = false;
bool webSocketStarted = false;
uint32_t connectedAt = 0;
uint32_t lastApplicationPingAt = 0;
uint32_t nextWebSocketRetryAt = 0;
uint32_t websocketRetryDelayMs = kWebSocketRetryBaseIntervalMs;
uint32_t lastNoServerLogAt = 0;
bool configMode = false;
bool lastButtonState = HIGH;
uint32_t lastButtonChangeAt = 0;
uint32_t configModeStartedAt = 0;
uint32_t lastConfigActivityAt = 0;
bool webServerStarted = false;
bool webRoutesRegistered = false;
char logLines[kLogCapacity][kLogLineLength];
uint8_t logCount = 0;
char wifiSnapshot[kWifiSnapshotBufferSize] = "{\"networks\":[]}";
char bluetoothSnapshot[kBluetoothSnapshotBufferSize] = "{\"devices\":[]}";
bool wifiSnapshotReady = false;
bool bluetoothSnapshotReady = false;
volatile uint32_t scanGeneration = 0;
uint32_t uploadedScanGeneration = 0;
SemaphoreHandle_t snapshotMutex = nullptr;
TaskHandle_t scanTaskHandle = nullptr;
uint64_t bluetoothSequence = 0;
uint64_t wifiSequence = 0;

void addLog(const String& message) {
    Serial.println(message);
    if (logCount < kLogCapacity) { message.substring(0, kLogLineLength - 1).toCharArray(logLines[logCount++], kLogLineLength); return; }
    for (uint8_t i = 1; i < kLogCapacity; ++i) memcpy(logLines[i - 1], logLines[i], kLogLineLength);
    message.substring(0, kLogLineLength - 1).toCharArray(logLines[kLogCapacity - 1], kLogLineLength);
}

String chipId() { const uint64_t id = ESP.getEfuseMac(); char value[17]{}; snprintf(value, sizeof(value), "%04x%08x", (uint16_t)(id >> 32), (uint32_t)id); return String(value); }
String digest(const String& password) { const String input = chipId() + ":" + password; uint8_t hash[32]; mbedtls_sha256((const unsigned char*)input.c_str(), input.length(), hash, 0); String result; result.reserve(64); for (uint8_t b : hash) { if (b < 16) result += "0"; result += String(b, HEX); } return result; }
bool constantEquals(const char* left, const String& right) { if (strlen(left) != right.length()) return false; uint8_t diff = 0; for (size_t i = 0; i < right.length(); ++i) diff |= left[i] ^ right[i]; return diff == 0; }
void copyField(char* destination, size_t capacity, const String& value) { value.toCharArray(destination, capacity); destination[capacity - 1] = '\0'; }
void copyField(char* destination, size_t capacity, const char* value) { String text(value ? value : ""); copyField(destination, capacity, text); }
uint8_t wifiCount() { uint8_t count = 0; while (count < kMaxWifiNetworks && config.wifi[count].ssid[0]) ++count; return count; }
bool hasAdminPassword() { return strlen(config.passwordHash) == kPasswordHashLength; }
bool hasConfig() { return wifiCount() > 0 && config.server.wsUrl[0] && config.server.token[0] && config.server.deviceId[0]; }
void setLed(bool on) { digitalWrite(kLedPin, on ? LOW : HIGH); }
void maintainLed() { static uint32_t nextFlashAt = 0; static bool flashing = false; const uint32_t now = millis(); if (configMode || WiFi.status() != WL_CONNECTED || !websocket.isConnected() || !authenticated) { setLed(true); flashing = false; return; } if (now - nextFlashAt >= 3000) { setLed(true); flashing = true; nextFlashAt = now; } else if (flashing && now - nextFlashAt >= 100) { setLed(false); flashing = false; } }
void markConfigActivity() { lastConfigActivityAt = millis(); }
String sessionToken;
uint32_t sessionCreatedAt = 0;
bool sessionIsValid() { if (!hasAdminPassword() || sessionToken.length() == 0 || millis() - sessionCreatedAt > kSessionTimeoutMs || !webServer.hasHeader("Cookie")) return false; const String cookie = webServer.header("Cookie"); const String expected = String("REMOTENV_SESSION=") + sessionToken; const int start = cookie.indexOf(expected); if (start < 0) return false; const int end = start + expected.length(); return (start == 0 || cookie[start - 1] == ' ' || cookie[start - 1] == ';') && (end == cookie.length() || cookie[end] == ';'); }
void createSession() { char token[kSessionTokenLength + 1]{}; for (uint8_t i = 0; i < kSessionTokenLength / 2; ++i) snprintf(token + i * 2, 3, "%02x", (uint8_t)esp_random()); sessionToken = token; sessionCreatedAt = millis(); }
void securityHeaders() { webServer.sendHeader("Cache-Control", "no-store"); webServer.sendHeader("Pragma", "no-cache"); webServer.sendHeader("X-Content-Type-Options", "nosniff"); webServer.sendHeader("X-Frame-Options", "DENY"); webServer.sendHeader("Connection", "keep-alive"); }
bool requireSession() { if (sessionIsValid()) return true; securityHeaders(); webServer.sendHeader("Location", "/login", true); webServer.send(302, "text/plain", "需要登录"); return false; }

void loadConfig() {
    Preferences p;
    p.begin("config", true);
    const String serialized = p.getString("json", "");
    p.end();
    memset(&config, 0, sizeof(config));
    if (serialized.length()) {
        DynamicJsonDocument doc(4096);
        if (deserializeJson(doc, serialized) == DeserializationError::Ok) {
            config.uploadIntervalSeconds = doc["interval"] | kDefaultUploadIntervalSeconds;
            copyField(config.passwordHash, sizeof(config.passwordHash), doc["password_hash"] | "");
            for (uint8_t i = 0; i < kMaxWifiNetworks; ++i) { copyField(config.wifi[i].ssid, sizeof(config.wifi[i].ssid), doc["wifi"][i]["ssid"] | ""); copyField(config.wifi[i].password, sizeof(config.wifi[i].password), doc["wifi"][i]["password"] | ""); }
            copyField(config.server.wsUrl, sizeof(config.server.wsUrl), doc["server"]["ws"] | ""); copyField(config.server.token, sizeof(config.server.token), doc["server"]["token"] | ""); copyField(config.server.deviceId, sizeof(config.server.deviceId), doc["server"]["device"] | "");
        }
    }
    if (!hasConfig()) {
        Preferences legacy;
        legacy.begin("legacy", true);
        copyField(config.wifi[0].ssid, sizeof(config.wifi[0].ssid), legacy.getString("ssid", "")); copyField(config.wifi[0].password, sizeof(config.wifi[0].password), legacy.getString("password", "")); copyField(config.server.wsUrl, sizeof(config.server.wsUrl), legacy.getString("ws", "")); copyField(config.server.token, sizeof(config.server.token), legacy.getString("token", "")); copyField(config.server.deviceId, sizeof(config.server.deviceId), legacy.getString("device", "")); copyField(config.passwordHash, sizeof(config.passwordHash), legacy.getString("hash", "")); config.uploadIntervalSeconds = legacy.getUInt("interval", kDefaultUploadIntervalSeconds); legacy.end();
    }
    if (config.uploadIntervalSeconds < kMinimumUploadIntervalSeconds || config.uploadIntervalSeconds > kMaximumUploadIntervalSeconds) config.uploadIntervalSeconds = kDefaultUploadIntervalSeconds;
    uploadIntervalSeconds = config.uploadIntervalSeconds;
}
void saveConfig() {
    DynamicJsonDocument doc(4096); doc["interval"] = config.uploadIntervalSeconds; doc["password_hash"] = config.passwordHash; JsonArray wifi = doc["wifi"].to<JsonArray>(); for (uint8_t i = 0; i < kMaxWifiNetworks; ++i) { JsonObject item = wifi.add<JsonObject>(); item["ssid"] = config.wifi[i].ssid; item["password"] = config.wifi[i].password; } JsonObject server = doc["server"].to<JsonObject>(); server["ws"] = config.server.wsUrl; server["token"] = config.server.token; server["device"] = config.server.deviceId; String serialized; serializeJson(doc, serialized); Preferences p; p.begin("config", false); p.putString("json", serialized); p.end(); }

uint64_t currentEpochMillis() { timeval now{}; gettimeofday(&now, nullptr); if (now.tv_sec < kMinimumValidEpoch) return 0; return (uint64_t)now.tv_sec * 1000ULL + now.tv_usec / 1000; }
uint64_t nextSequence(uint64_t& last, const char* key, uint64_t now) { const uint64_t candidate = last == UINT64_MAX ? UINT64_MAX : last + 1; last = now > candidate ? now : candidate; sequencePreferences.putULong64(key, last); return last; }
void loadSequences() { sequencePreferences.begin("sequence", false); bluetoothSequence = sequencePreferences.getULong64("bluetooth", 0); wifiSequence = sequencePreferences.getULong64("wifi", 0); }

bool parseWsUrl(const char* url, String& host, uint16_t& port, String& path, bool& secure) { String value(url); value.trim(); secure = value.startsWith("wss://"); String scheme = secure ? "wss://" : "ws://"; if (!value.startsWith(scheme)) return false; String authorityPath = value.substring(scheme.length()); int slash = authorityPath.indexOf('/'); String authority = slash >= 0 ? authorityPath.substring(0, slash) : authorityPath; path = slash >= 0 ? authorityPath.substring(slash) : "/"; if (!authority.length()) return false; int colon = authority.lastIndexOf(':'); if (colon > 0 && authority.indexOf(']') < colon) { host = authority.substring(0, colon); long valuePort = authority.substring(colon + 1).toInt(); if (valuePort < 1 || valuePort > 65535) return false; port = valuePort; } else { host = authority; port = secure ? 443 : 80; } return host.length() > 0; }
void sendAuth() { StaticJsonDocument<512> message; message["type"] = "auth"; message["role"] = "collector"; message["token"] = config.server.token; message["device_id"] = config.server.deviceId; JsonObject device = message["device"].to<JsonObject>(); device["name"] = "ESP32-C3 WiFi/Bluetooth Collector"; device["device_type"] = "esp32-c3"; JsonArray caps = device["capabilities"].to<JsonArray>(); caps.add("wifi"); caps.add("bluetooth"); String payload; serializeJson(message, payload); websocket.sendTXT(payload); addLog("发送 WebSocket 认证"); }

String base64Encode(const uint8_t* data, size_t length) { static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; String result; result.reserve(((length + 2) / 3) * 4); for (size_t i = 0; i < length; i += 3) { uint32_t value = ((uint32_t)data[i] << 16) | (i + 1 < length ? (uint32_t)data[i + 1] << 8 : 0) | (i + 2 < length ? data[i + 2] : 0); result += alphabet[(value >> 18) & 63]; result += alphabet[(value >> 12) & 63]; result += i + 1 < length ? alphabet[(value >> 6) & 63] : '='; result += i + 2 < length ? alphabet[value & 63] : '='; } return result; }
String bytesToHex(const uint8_t* data, size_t length) { String result; result.reserve(length * 2); for (size_t i = 0; i < length; ++i) { if (data[i] < 16) result += '0'; result += String(data[i], HEX); } return result; }
void scanBluetoothSnapshot(uint32_t durationMs) { uint64_t started = currentEpochMillis(); NimBLEScan* scanner = NimBLEDevice::getScan(); scanner->setActiveScan(true); scanner->setInterval(100); scanner->setWindow(100); scanner->setMaxResults(20); scanner->setDuplicateFilter(1); NimBLEScanResults results = scanner->getResults(durationMs, false); DynamicJsonDocument doc(8192); JsonArray devices = doc["devices"].to<JsonArray>(); for (int i = 0; i < results.getCount(); ++i) { const NimBLEAdvertisedDevice* device = results.getDevice(i); JsonObject item = devices.add<JsonObject>(); item["name"] = device->haveName() ? device->getName().c_str() : ""; item["address"] = device->getAddress().toString().c_str(); item["rssi"] = device->getRSSI(); item["address_type"] = "unknown"; if (device->haveTXPower()) item["tx_power"] = device->getTXPower(); if (device->haveServiceUUID()) { JsonArray uuids = item["service_uuids"].to<JsonArray>(); for (int j = 0; j < device->getServiceUUIDCount(); ++j) uuids.add(device->getServiceUUID(j).toString().c_str()); } if (device->haveManufacturerData()) { std::string raw = device->getManufacturerData(0); if (raw.length() >= 2) item["manufacturer_id"] = (uint16_t)(uint8_t)raw[0] | ((uint16_t)(uint8_t)raw[1] << 8); item["manufacturer_data"] = base64Encode((const uint8_t*)raw.data(), raw.length()); } const std::vector<uint8_t>& raw = device->getPayload(); item["rawHex"] = bytesToHex(raw.data(), raw.size()); item["rawLength"] = raw.size(); item["raw"] = base64Encode(raw.data(), raw.size()); item["timestamp"] = currentEpochMillis(); } doc["scan_started_at"] = started; doc["scan_finished_at"] = currentEpochMillis(); doc["technology"] = "ble"; doc["is_enabled"] = true; String encoded; serializeJson(doc, encoded); if (encoded.length() < sizeof(bluetoothSnapshot)) { if (snapshotMutex) xSemaphoreTake(snapshotMutex, portMAX_DELAY); encoded.toCharArray(bluetoothSnapshot, sizeof(bluetoothSnapshot)); bluetoothSnapshotReady = true; if (snapshotMutex) xSemaphoreGive(snapshotMutex); } scanner->clearResults(); addLog(String("Bluetooth 扫描完成：") + results.getCount() + " 个"); }
void scanWifiSnapshot(uint32_t durationMs) { uint64_t started = currentEpochMillis(); uint32_t perChannelMs = max<uint32_t>(100, durationMs / 14); int count = WiFi.scanNetworks(false, true, false, perChannelMs); DynamicJsonDocument doc(6144); JsonArray networks = doc["networks"].to<JsonArray>(); for (int i = 0; i < count; ++i) { JsonObject item = networks.add<JsonObject>(); item["ssid"] = WiFi.SSID(i); item["bssid"] = WiFi.BSSIDstr(i); item["rssi"] = WiFi.RSSI(i); item["channel"] = WiFi.channel(i); item["frequency_mhz"] = WiFi.channel(i) <= 14 ? 2407 + WiFi.channel(i) * 5 : 5000 + WiFi.channel(i) * 5; JsonArray security = item["security"].to<JsonArray>(); security.add(WiFi.encryptionType(i) == WIFI_AUTH_OPEN ? "OPEN" : "WPA2-PSK"); item["hidden"] = WiFi.SSID(i).length() == 0; item["timestamp"] = currentEpochMillis(); } doc["scan_started_at"] = started; doc["scan_finished_at"] = currentEpochMillis(); doc["interface"] = "wlan0"; doc["is_connected"] = WiFi.status() == WL_CONNECTED; if (WiFi.status() == WL_CONNECTED) { doc["ip_address"] = WiFi.localIP().toString(); doc["gateway"] = WiFi.gatewayIP().toString(); doc["dns_servers"].add(WiFi.dnsIP().toString()); } String encoded; serializeJson(doc, encoded); if (encoded.length() < sizeof(wifiSnapshot)) { if (snapshotMutex) xSemaphoreTake(snapshotMutex, portMAX_DELAY); encoded.toCharArray(wifiSnapshot, sizeof(wifiSnapshot)); wifiSnapshotReady = true; if (snapshotMutex) xSemaphoreGive(snapshotMutex); } WiFi.scanDelete(); addLog(String("WiFi 扫描完成：") + count + " 个"); }
void runScanCycle() { uint32_t total = constrain(uploadIntervalSeconds, kMinimumUploadIntervalSeconds, kMaximumUploadIntervalSeconds) * 1000UL; scanBluetoothSnapshot(total / 2); scanWifiSnapshot(total / 2); ++scanGeneration; }
void scanWorker(void*) { for (;;) { if (!configMode && WiFi.status() == WL_CONNECTED) runScanCycle(); vTaskDelay(pdMS_TO_TICKS(uploadIntervalSeconds * 1000UL)); } }

void sendEnvironmentData(const char* type, const char* dataJson, uint64_t sequence, uint64_t timestamp) { DynamicJsonDocument message(16384); message["type"] = "environment_data"; message["version"] = 1; message["device_id"] = config.server.deviceId; message["data_type"] = type; message["timestamp"] = timestamp; message["sequence"] = sequence; DynamicJsonDocument data(12288); if (deserializeJson(data, dataJson) != DeserializationError::Ok) return; message["data"] = data.as<JsonObject>(); String payload; payload.reserve(16384); serializeJson(message, payload); if (authenticated && websocket.isConnected()) { bool sent = websocket.sendTXT(payload); addLog(String("上传 ") + type + (sent ? " 已发送" : " 发送失败")); } data.clear(); message.clear(); payload = String(); }
void sendCombinedSnapshot() { if (!authenticated || !websocket.isConnected() || scanGeneration == uploadedScanGeneration) return; String wifiCopy, bluetoothCopy; bool wifiReady, bluetoothReady; if (snapshotMutex) xSemaphoreTake(snapshotMutex, portMAX_DELAY); wifiCopy = wifiSnapshot; bluetoothCopy = bluetoothSnapshot; wifiReady = wifiSnapshotReady; bluetoothReady = bluetoothSnapshotReady; if (snapshotMutex) xSemaphoreGive(snapshotMutex); if (!wifiReady) wifiCopy = "{\"networks\":[]}"; if (!bluetoothReady) bluetoothCopy = "{\"devices\":[]}"; uint64_t timestamp = currentEpochMillis(); if (!timestamp) return; sendEnvironmentData(kBluetoothDataType, bluetoothCopy.c_str(), nextSequence(bluetoothSequence, "bluetooth", timestamp), timestamp); bluetoothCopy = String(); yield(); sendEnvironmentData(kWifiDataType, wifiCopy.c_str(), nextSequence(wifiSequence, "wifi", timestamp), timestamp); wifiCopy = String(); uploadedScanGeneration = scanGeneration; addLog("数据已上传"); }
void onWebSocketEvent(WStype_t type, uint8_t* payload, size_t length) { switch (type) { case WStype_CONNECTED: authenticated = false; connectedAt = millis(); lastApplicationPingAt = millis() + kApplicationPingIntervalMs; websocketRetryDelayMs = kWebSocketRetryBaseIntervalMs; addLog("WebSocket 已连接，发送认证"); sendAuth(); break; case WStype_DISCONNECTED: authenticated = false; connectedAt = 0; webSocketStarted = false; nextWebSocketRetryAt = millis() + websocketRetryDelayMs; addLog(String("WebSocket 已断开，") + websocketRetryDelayMs / 1000 + " 秒后重连"); websocketRetryDelayMs = min<uint32_t>(websocketRetryDelayMs * 2, kWebSocketRetryMaximumIntervalMs); break; case WStype_ERROR: addLog("WebSocket 库报告连接错误"); break; case WStype_PONG: break; case WStype_TEXT: { StaticJsonDocument<1024> message; if (deserializeJson(message, payload, length) != DeserializationError::Ok) break; const char* messageType = message["type"] | ""; if (!strcmp(messageType, "auth_result")) { authenticated = message["success"] | false; if (authenticated) { websocketRetryDelayMs = kWebSocketRetryBaseIntervalMs; addLog("WebSocket 认证成功"); } else addLog("WebSocket 认证失败"); } else if (!strcmp(messageType, "ping")) websocket.sendTXT("{\"type\":\"ping\"}"); else if (!strcmp(messageType, "data_result")) addLog(String("服务器确认 ") + (message["data_type"] | "unknown")); break; } default: break; } }

void sendLoginPage(const String& error = "") { String page; page.reserve(2500); page += F("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>RemoteEnv 登录</title></head><body><main><h1>ESP32-C3 管理登录</h1>"); if (error.length()) { page += F("<p>"); page += error; page += F("</p>"); } page += F("<form method='post' action='/login'><label>管理密码<input name='password' type='password' minlength='8' maxlength='96' required autofocus></label><button type='submit'>登录</button></form></main></body></html>"); securityHeaders(); webServer.send(200, "text/html; charset=utf-8", page); }
void handleLogin() { markConfigActivity(); if (!hasAdminPassword()) { webServer.sendHeader("Location", "/setup-password", true); webServer.send(302, "text/plain", "请先设置管理密码"); return; } if (!webServer.hasArg("password") || !constantEquals(config.passwordHash, digest(webServer.arg("password")))) { sendLoginPage("密码错误"); return; } createSession(); securityHeaders(); webServer.sendHeader("Set-Cookie", String("REMOTENV_SESSION=") + sessionToken + "; Max-Age=1800; HttpOnly; SameSite=Strict; Path=/", true); webServer.sendHeader("Location", "/", true); webServer.send(302, "text/plain", "登录成功"); }
void handleSetupPassword() { if (hasAdminPassword()) { if (!requireSession()) return; } String page = "<form method='post' action='/setup-password'><input name='password' type='password' minlength='8' required><input name='confirm' type='password' minlength='8' required><button>设置</button></form>"; securityHeaders(); webServer.send(200, "text/html; charset=utf-8", page); }
void handleSetupPasswordPost() { if (hasAdminPassword()) { webServer.send(403, "text/plain", "管理密码已经设置"); return; } String password = webServer.arg("password"); if (password.length() < 8 || password.length() > 96 || password != webServer.arg("confirm")) { handleSetupPassword(); return; } copyField(config.passwordHash, sizeof(config.passwordHash), digest(password)); saveConfig(); createSession(); webServer.sendHeader("Location", "/", true); webServer.send(302, "text/plain", "密码已设置"); }
void handleLogout() { sessionToken = ""; securityHeaders(); webServer.sendHeader("Location", "/login", true); webServer.send(302, "text/plain", "已退出"); }
String htmlEscape(const char* value) { String result(value ? value : ""); result.replace("&", "&amp;"); result.replace("<", "&lt;"); result.replace(">", "&gt;"); result.replace("\"", "&quot;"); result.replace("'", "&#39;"); return result; }
void handleConfigPage() { markConfigActivity(); if (!hasAdminPassword()) { webServer.sendHeader("Location", "/setup-password", true); webServer.send(302, "text/plain", "请先设置管理密码"); return; } if (!requireSession()) return; String page; page.reserve(10000); page += F("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>RemoteEnv 配置</title><style>body{font-family:system-ui,sans-serif;background:#f3f5f7;margin:0;padding:24px}main{max-width:680px;margin:auto;background:#fff;padding:24px;border-radius:12px}label{display:block;margin-top:12px;font-weight:600}input{box-sizing:border-box;width:100%;padding:9px;margin-top:4px}button{margin-top:18px;padding:10px 18px}</style></head><body><main><h1>ESP32-C3 环境采集器配置</h1><p>服务器为单服务器稳定模式；WiFi 支持最多 5 组，按顺序轮询。</p><form method='post' action='/save'><h2>WiFi 列表</h2>"); for (uint8_t i = 0; i < kMaxWifiNetworks; ++i) { page += F("<fieldset><legend>WiFi "); page += i + 1; page += F("</legend><label>名称<input name='ssid"); page += i; page += F("' maxlength='63' value='"); page += htmlEscape(config.wifi[i].ssid); page += F("'></label><label>密码<input name='password"); page += i; page += F("' type='password' maxlength='63' value='"); page += htmlEscape(config.wifi[i].password); page += F("'></label></fieldset>"); } page += F("<h2>服务器</h2><label>WS 地址<input name='ws' maxlength='159' required value='"); page += htmlEscape(config.server.wsUrl); page += F("'></label><label>Token<input name='token' maxlength='159' required value='"); page += htmlEscape(config.server.token); page += F("'></label><label>设备 ID<input name='serverDevice' maxlength='63' required value='"); page += htmlEscape(config.server.deviceId); page += F("'></label><label>上传间隔（秒，10-30）<input name='interval' type='number' min='10' max='30' required value='"); page += uploadIntervalSeconds; page += F("'></label><button type='submit'>保存并重启</button></form><p><a href='/panel'>运行面板</a> · <form method='post' action='/logout'><button>退出登录</button></form></p></main></body></html>"); securityHeaders(); webServer.send(200, "text/html; charset=utf-8", page); }
void handlePanel() { markConfigActivity(); if (!requireSession()) return; String page; page.reserve(4000); page += F("<meta charset='utf-8'><h1>ESP32-C3 运行面板</h1><p>WiFi："); page += WiFi.status() == WL_CONNECTED ? F("已连接 ") : F("未连接 "); page += WiFi.localIP().toString(); page += F("<br>服务器："); page += authenticated && websocket.isConnected() ? F("已认证") : F("未连接/未认证"); page += F("<br>设备 ID："); page += htmlEscape(config.server.deviceId); page += F("</p><pre>"); for (uint8_t i = 0; i < logCount; ++i) { page += htmlEscape(logLines[i]); page += '\n'; } page += F("</pre><p><a href='/'>配置页面</a></p>"); securityHeaders(); webServer.send(200, "text/html; charset=utf-8", page); }
void handleSaveConfig() { if (!requireSession()) return; DeviceConfig requested{}; uint8_t wifiWriteIndex = 0; for (uint8_t i = 0; i < kMaxWifiNetworks; ++i) { String ssid = webServer.arg(String("ssid") + i); if (!ssid.length()) continue; if (wifiWriteIndex >= kMaxWifiNetworks) break; copyField(requested.wifi[wifiWriteIndex].ssid, sizeof(requested.wifi[wifiWriteIndex].ssid), ssid); copyField(requested.wifi[wifiWriteIndex].password, sizeof(requested.wifi[wifiWriteIndex].password), webServer.arg(String("password") + i)); ++wifiWriteIndex; } String ws = webServer.arg("ws"); String host, path; uint16_t port; bool secure; if (!wifiWriteIndex || !parseWsUrl(ws.c_str(), host, port, path, secure) || !webServer.arg("token").length() || !webServer.arg("serverDevice").length()) { webServer.send(400, "text/plain; charset=utf-8", "至少配置一个 WiFi，且服务器地址、Token、设备 ID 必须完整"); return; } requested.server = {}; copyField(requested.server.wsUrl, sizeof(requested.server.wsUrl), ws); copyField(requested.server.token, sizeof(requested.server.token), webServer.arg("token")); copyField(requested.server.deviceId, sizeof(requested.server.deviceId), webServer.arg("serverDevice")); copyField(requested.passwordHash, sizeof(requested.passwordHash), config.passwordHash); long interval = webServer.arg("interval").toInt(); if (interval < 10 || interval > 30) { webServer.send(400, "text/plain", "上传间隔必须是 10 到 30 秒"); return; } requested.uploadIntervalSeconds = interval; String newPassword = webServer.arg("newPassword"); if (newPassword.length()) { if (newPassword.length() < 8 || newPassword != webServer.arg("confirmPassword")) { webServer.send(400, "text/plain", "新密码无效"); return; } copyField(requested.passwordHash, sizeof(requested.passwordHash), digest(newPassword)); } config = requested; saveConfig(); sessionToken = ""; webServer.send(200, "text/html; charset=utf-8", "<meta charset='utf-8'><p>配置已保存，设备正在重启...</p>"); delay(500); ESP.restart(); }
void registerWebRoutes() { if (webRoutesRegistered) return; webRoutesRegistered = true; const char* headers[] = {"Cookie"}; webServer.collectHeaders(headers, 1); webServer.on("/", HTTP_GET, handleConfigPage); webServer.on("/login", HTTP_GET, []() { sendLoginPage(); }); webServer.on("/login", HTTP_POST, handleLogin); webServer.on("/setup-password", HTTP_GET, handleSetupPassword); webServer.on("/setup-password", HTTP_POST, handleSetupPasswordPost); webServer.on("/logout", HTTP_POST, handleLogout); webServer.on("/panel", HTTP_GET, handlePanel); webServer.on("/save", HTTP_POST, handleSaveConfig); webServer.onNotFound([]() { webServer.send(404, "text/plain", "Not found"); }); }
void startLocalWebServer() { registerWebRoutes(); if (!webServerStarted) { webServer.begin(); webServerStarted = true; } }
void startConfigMode() { if (configMode) return; configMode = true; configModeStartedAt = millis(); lastConfigActivityAt = configModeStartedAt; authenticated = false; webSocketStarted = false; websocket.disconnect(); WiFi.disconnect(true); WiFi.mode(WIFI_AP); String name = String("RemoteEnv-Setup-") + chipId(); WiFi.softAP(name.c_str(), kApPassword); startLocalWebServer(); addLog(String("配置 AP：") + name + "，访问 http://" + WiFi.softAPIP().toString() + "/"); }
void beginWifiAttempt() { WiFi.mode(WIFI_STA); WiFi.begin(config.wifi[wifiIndex].ssid, config.wifi[wifiIndex].password); wifiAttemptStartedAt = millis(); wifiConnecting = true; addLog(String("尝试连接 WiFi ") + (wifiIndex + 1) + "：" + config.wifi[wifiIndex].ssid); }
void maintainWifi() { uint32_t now = millis(); if (WiFi.status() == WL_CONNECTED) { if (wifiConnecting) { wifiConnecting = false; wifiRetryDelayMs = kWifiRetryBaseIntervalMs; wifiRound = 0; nextWebSocketRetryAt = now; addLog(String("WiFi 已连接：") + WiFi.localIP().toString()); setenv("TZ", "CST-8", 1); tzset(); configTime(0, 0, "ntp1.aliyun.com", "pool.ntp.org", "time.nist.gov"); } return; } authenticated = false; if (webSocketStarted) { websocket.disconnect(); webSocketStarted = false; } if (wifiConnecting && now - wifiAttemptStartedAt < kWifiConnectTimeoutMs) return; if (wifiConnecting) { wifiConnecting = false; WiFi.disconnect(); ++wifiIndex; if (wifiIndex >= wifiCount()) { wifiIndex = 0; ++wifiRound; nextWifiRetryAt = now + wifiRetryDelayMs; addLog(String("WiFi 第 ") + wifiRound + " 轮失败，" + wifiRetryDelayMs / 1000 + " 秒后重试"); wifiRetryDelayMs = min<uint32_t>(wifiRetryDelayMs * 2, kWifiRetryMaximumIntervalMs); } else nextWifiRetryAt = now + 250; } if (static_cast<int32_t>(now - nextWifiRetryAt) >= 0) { nextWifiRetryAt = UINT32_MAX; beginWifiAttempt(); } }
void startWebSocket() { if (webSocketStarted || !hasConfig() || WiFi.status() != WL_CONNECTED) return; String host, path; uint16_t port; bool secure; if (!parseWsUrl(config.server.wsUrl, host, port, path, secure)) { nextWebSocketRetryAt = millis() + websocketRetryDelayMs; return; } if (secure) websocket.beginSSL(host.c_str(), port, path.c_str(), nullptr, "arduino"); else websocket.begin(host.c_str(), port, path.c_str(), "arduino"); websocket.onEvent(onWebSocketEvent); websocket.setReconnectInterval(websocketRetryDelayMs); websocket.enableHeartbeat(30000, 5000, 2); webSocketStarted = true; addLog("开始 WebSocket 稳定重连"); }
void maintainWebSocket() { uint32_t now = millis(); if (websocket.isConnected() && !authenticated && connectedAt && now - connectedAt >= kAuthTimeoutMs) { addLog("WebSocket 认证超时，主动断开"); websocket.disconnect(); webSocketStarted = false; nextWebSocketRetryAt = now + websocketRetryDelayMs; } if (!websocket.isConnected() && static_cast<int32_t>(now - nextWebSocketRetryAt) >= 0) { nextWebSocketRetryAt = now + websocketRetryDelayMs; startWebSocket(); } if (authenticated && websocket.isConnected() && now - lastApplicationPingAt >= kApplicationPingIntervalMs) { websocket.sendTXT("{\"type\":\"ping\"}"); lastApplicationPingAt = now; } }
void checkConfigButton() { static bool initialized = false; static bool lastState = HIGH; static uint32_t changedAt = 0; const bool state = digitalRead(kConfigButtonPin); const uint32_t now = millis(); if (!initialized) { initialized = true; lastState = state; changedAt = now; return; } if (state != lastState) { lastState = state; changedAt = now; addLog(state == LOW ? "BOOT 按钮按下，GPIO9" : "BOOT 按钮释放，GPIO9"); } if (state == LOW && now - changedAt >= 40) startConfigMode(); }
}

void setup() { Serial.begin(115200); delay(100); Serial.println("RemoteEnv ESP32-C3 boot"); pinMode(kLedPin, OUTPUT); setLed(true); pinMode(kConfigButtonPin, INPUT_PULLUP); Serial.println("BOOT button candidate: GPIO9"); Serial.printf("LED GPIO=%u active-low: LOW=ON HIGH=OFF\n", kLedPin); NimBLEDevice::init(""); loadConfig(); loadSequences(); snapshotMutex = xSemaphoreCreateMutex(); if (snapshotMutex) xTaskCreatePinnedToCore(scanWorker, "env-scan", 8192, nullptr, 1, &scanTaskHandle, 0); if (!hasConfig() || digitalRead(kConfigButtonPin) == LOW) { startConfigMode(); return; } nextWifiRetryAt = 0; beginWifiAttempt(); startLocalWebServer(); }
void loop() { maintainLed(); checkConfigButton(); if (configMode) { webServer.handleClient(); if (configMode && hasConfig() && millis() - lastConfigActivityAt >= kConfigModeTimeoutMs) ESP.restart(); delay(2); return; } webServer.handleClient(); maintainWifi(); if (WiFi.status() == WL_CONNECTED) { websocket.loop(); maintainWebSocket(); sendCombinedSnapshot(); } maintainLed(); delay(2); }
