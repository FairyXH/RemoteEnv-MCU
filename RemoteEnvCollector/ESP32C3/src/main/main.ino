#include <Arduino.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <WebServer.h>
#include <NimBLEDevice.h>
#include <WiFi.h>
#include <WebSocketsClient.h>
#include <mbedtls/sha256.h>
#include <sys/time.h>
#include <time.h>

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
constexpr uint32_t kUploadIntervalSec = 15;
constexpr uint32_t kMinUploadSec = 10;
constexpr uint32_t kMaxUploadSec = 30;
constexpr size_t kWifiBufferSize = 8192;
constexpr size_t kBleBufferSize = 8192;
constexpr size_t kLogCapacity = 24;
constexpr size_t kLogLineSize = 112;
constexpr time_t kMinimumEpoch = 1700000000;
constexpr char kApPassword[] = "12345678";

struct WifiProfile { char ssid[64]; char password[64]; };
struct ServerProfile { char ws[160]; char token[160]; char device[64]; };
struct Config { WifiProfile wifi[kMaxWifi]; ServerProfile server; char passwordHash[65]; uint32_t interval; };

Config config{};
Preferences configStore;
Preferences sequenceStore;
WebServer web(80);
WebSocketsClient ws;
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
uint32_t nextScanAt = 0;
uint32_t scanGeneration = 0;
uint32_t uploadedGeneration = 0;
bool configMode = false;
bool wifiConnecting = false;
bool wsStarted = false;
bool authenticated = false;
bool bleReady = false;
bool wifiReady = false;
SemaphoreHandle_t snapshotMutex = nullptr;
TaskHandle_t scanTaskHandle = nullptr;
char wifiSnapshot[kWifiBufferSize] = "{\"networks\":[]}";
char bleSnapshot[kBleBufferSize] = "{\"devices\":[]}";
char logs[kLogCapacity][kLogLineSize]{};
uint8_t logCount = 0;
uint64_t wifiSequence = 0;
uint64_t bleSequence = 0;

void logLine(const String& text) {
    Serial.println(text);
    if (logCount < kLogCapacity) { text.substring(0, kLogLineSize - 1).toCharArray(logs[logCount++], kLogLineSize); return; }
    for (uint8_t i = 1; i < kLogCapacity; ++i) memcpy(logs[i - 1], logs[i], kLogLineSize);
    text.substring(0, kLogLineSize - 1).toCharArray(logs[kLogCapacity - 1], kLogLineSize);
}
String escapeHtml(const char* value) { String r(value ? value : ""); r.replace("&", "&amp;"); r.replace("<", "&lt;"); r.replace(">", "&gt;"); r.replace("\"", "&quot;"); r.replace("'", "&#39;"); return r; }
String chipId() { uint64_t id = ESP.getEfuseMac(); char text[17]{}; snprintf(text, sizeof(text), "%04x%08x", (uint16_t)(id >> 32), (uint32_t)id); return String(text); }
String passwordHash(const String& password) { String input = chipId() + ":" + password; uint8_t hash[32]; mbedtls_sha256((const unsigned char*)input.c_str(), input.length(), hash, 0); String out; out.reserve(64); for (uint8_t b : hash) { if (b < 16) out += '0'; out += String(b, HEX); } return out; }
bool constantEquals(const char* left, const String& right) { if (strlen(left) != right.length()) return false; uint8_t diff = 0; for (size_t i = 0; i < right.length(); ++i) diff |= (uint8_t)(left[i] ^ right[i]); return diff == 0; }
void copyText(char* target, size_t capacity, const String& value) { value.toCharArray(target, capacity); target[capacity - 1] = 0; }
uint8_t wifiCount() { uint8_t n = 0; while (n < kMaxWifi && config.wifi[n].ssid[0]) ++n; return n; }
bool hasPassword() { return strlen(config.passwordHash) == 64; }
bool hasConfig() { return wifiCount() > 0 && config.server.ws[0] && config.server.token[0] && config.server.device[0]; }
void touchConfig() { lastConfigActivityAt = millis(); }
bool sessionValid() { if (!hasPassword() || !session.length() || millis() - sessionAt > 1800000 || !web.hasHeader("Cookie")) return false; String cookie = web.header("Cookie"); String expected = String("REMOTENV_SESSION=") + session; int p = cookie.indexOf(expected); if (p < 0) return false; int end = p + expected.length(); return (p == 0 || cookie[p - 1] == ' ' || cookie[p - 1] == ';') && (end == cookie.length() || cookie[end] == ';'); }
void headers() { web.sendHeader("Cache-Control", "no-store"); web.sendHeader("Pragma", "no-cache"); web.sendHeader("X-Content-Type-Options", "nosniff"); web.sendHeader("X-Frame-Options", "DENY"); web.sendHeader("Connection", "keep-alive"); }
bool requireLogin() { if (sessionValid()) return true; headers(); web.sendHeader("Location", "/login", true); web.send(302, "text/plain; charset=utf-8", "需要登录"); return false; }
void createSession() { char value[33]{}; for (uint8_t i = 0; i < 16; ++i) snprintf(value + i * 2, 3, "%02x", (uint8_t)esp_random()); session = value; sessionAt = millis(); }
uint64_t epochMs() { timeval tv{}; gettimeofday(&tv, nullptr); if (tv.tv_sec < kMinimumEpoch) return 0; return (uint64_t)tv.tv_sec * 1000ULL + tv.tv_usec / 1000; }

void loadConfig() {
    configStore.begin("config", true);
    String json = configStore.getString("json", "");
    configStore.end();
    memset(&config, 0, sizeof(config));
    config.interval = kUploadIntervalSec;
    if (json.length()) {
        DynamicJsonDocument doc(4096);
        if (deserializeJson(doc, json) == DeserializationError::Ok) {
            config.interval = doc["interval"] | kUploadIntervalSec;
            copyText(config.passwordHash, sizeof(config.passwordHash), doc["password_hash"] | "");
            for (uint8_t i = 0; i < kMaxWifi; ++i) { copyText(config.wifi[i].ssid, sizeof(config.wifi[i].ssid), doc["wifi"][i]["ssid"] | ""); copyText(config.wifi[i].password, sizeof(config.wifi[i].password), doc["wifi"][i]["password"] | ""); }
            copyText(config.server.ws, sizeof(config.server.ws), doc["server"]["ws"] | "");
            copyText(config.server.token, sizeof(config.server.token), doc["server"]["token"] | "");
            copyText(config.server.device, sizeof(config.server.device), doc["server"]["device"] | "");
        }
    }
    if (config.interval < kMinUploadSec || config.interval > kMaxUploadSec) config.interval = kUploadIntervalSec;
}
void saveConfig() {
    DynamicJsonDocument doc(4096);
    doc["interval"] = config.interval;
    doc["password_hash"] = config.passwordHash;
    JsonArray wifi = doc["wifi"].to<JsonArray>();
    for (uint8_t i = 0; i < kMaxWifi; ++i) { JsonObject item = wifi.add<JsonObject>(); item["ssid"] = config.wifi[i].ssid; item["password"] = config.wifi[i].password; }
    JsonObject server = doc["server"].to<JsonObject>(); server["ws"] = config.server.ws; server["token"] = config.server.token; server["device"] = config.server.device;
    String json; serializeJson(doc, json); configStore.begin("config", false); configStore.putString("json", json); configStore.end();
}
void loadSequences() { sequenceStore.begin("sequence", false); wifiSequence = sequenceStore.getULong64("wifi", 0); bleSequence = sequenceStore.getULong64("bluetooth", 0); }
uint64_t nextSequence(uint64_t& previous, const char* key, uint64_t now) { uint64_t candidate = previous == UINT64_MAX ? UINT64_MAX : previous + 1; previous = now > candidate ? now : candidate; sequenceStore.putULong64(key, previous); return previous; }

bool parseWs(const char* url, String& host, uint16_t& port, String& path, bool& secure) { String value(url); value.trim(); secure = value.startsWith("wss://"); String scheme = secure ? "wss://" : "ws://"; if (!value.startsWith(scheme)) return false; String authorityPath = value.substring(scheme.length()); int slash = authorityPath.indexOf('/'); String authority = slash >= 0 ? authorityPath.substring(0, slash) : authorityPath; path = slash >= 0 ? authorityPath.substring(slash) : "/"; if (!authority.length()) return false; int colon = authority.lastIndexOf(':'); if (colon > 0 && authority.indexOf(']') < colon) { host = authority.substring(0, colon); long p = authority.substring(colon + 1).toInt(); if (p < 1 || p > 65535) return false; port = (uint16_t)p; } else { host = authority; port = secure ? 443 : 80; } return host.length() > 0; }
String base64(const uint8_t* data, size_t length) { static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; String out; out.reserve(((length + 2) / 3) * 4); for (size_t i = 0; i < length; i += 3) { uint32_t v = ((uint32_t)data[i] << 16) | (i + 1 < length ? (uint32_t)data[i + 1] << 8 : 0) | (i + 2 < length ? data[i + 2] : 0); out += table[(v >> 18) & 63]; out += table[(v >> 12) & 63]; out += i + 1 < length ? table[(v >> 6) & 63] : '='; out += i + 2 < length ? table[v & 63] : '='; } return out; }
String hexBytes(const uint8_t* data, size_t length) { String out; out.reserve(length * 2); for (size_t i = 0; i < length; ++i) { if (data[i] < 16) out += '0'; out += String(data[i], HEX); } return out; }

void scanBluetooth(uint32_t durationMs) { uint64_t started = epochMs(); NimBLEScan* scan = NimBLEDevice::getScan(); scan->setActiveScan(true); scan->setInterval(100); scan->setWindow(100); scan->setMaxResults(20); scan->setDuplicateFilter(1); NimBLEScanResults results = scan->getResults(durationMs, false); DynamicJsonDocument doc(8192); JsonArray devices = doc["devices"].to<JsonArray>(); for (int i = 0; i < results.getCount(); ++i) { const NimBLEAdvertisedDevice* d = results.getDevice(i); JsonObject item = devices.add<JsonObject>(); item["name"] = d->haveName() ? d->getName().c_str() : ""; item["address"] = d->getAddress().toString().c_str(); item["rssi"] = d->getRSSI(); item["address_type"] = "unknown"; if (d->haveTXPower()) item["tx_power"] = d->getTXPower(); if (d->haveServiceUUID()) { JsonArray uuids = item["service_uuids"].to<JsonArray>(); for (int j = 0; j < d->getServiceUUIDCount(); ++j) uuids.add(d->getServiceUUID(j).toString().c_str()); } const std::vector<uint8_t>& raw = d->getPayload(); item["raw"] = base64(raw.data(), raw.size()); item["rawHex"] = hexBytes(raw.data(), raw.size()); item["rawLength"] = raw.size(); item["timestamp"] = epochMs(); } doc["scan_started_at"] = started; doc["scan_finished_at"] = epochMs(); doc["technology"] = "ble"; doc["is_enabled"] = true; String encoded; serializeJson(doc, encoded); if (encoded.length() < sizeof(bleSnapshot)) { if (snapshotMutex) xSemaphoreTake(snapshotMutex, portMAX_DELAY); encoded.toCharArray(bleSnapshot, sizeof(bleSnapshot)); bleReady = true; if (snapshotMutex) xSemaphoreGive(snapshotMutex); } scan->clearResults(); logLine(String("Bluetooth 扫描完成：") + results.getCount() + " 个"); }
void scanWifi(uint32_t durationMs) { uint64_t started = epochMs(); int count = WiFi.scanNetworks(false, true, false, max<uint32_t>(100, durationMs / 14)); DynamicJsonDocument doc(6144); JsonArray networks = doc["networks"].to<JsonArray>(); for (int i = 0; i < count; ++i) { JsonObject item = networks.add<JsonObject>(); item["ssid"] = WiFi.SSID(i); item["bssid"] = WiFi.BSSIDstr(i); item["rssi"] = WiFi.RSSI(i); item["channel"] = WiFi.channel(i); item["frequency_mhz"] = WiFi.channel(i) <= 14 ? 2407 + WiFi.channel(i) * 5 : 5000 + WiFi.channel(i) * 5; JsonArray security = item["security"].to<JsonArray>(); security.add(WiFi.encryptionType(i) == WIFI_AUTH_OPEN ? "OPEN" : "WPA2-PSK"); item["hidden"] = WiFi.SSID(i).length() == 0; item["timestamp"] = epochMs(); } doc["scan_started_at"] = started; doc["scan_finished_at"] = epochMs(); doc["interface"] = "wlan0"; doc["is_connected"] = WiFi.status() == WL_CONNECTED; if (WiFi.status() == WL_CONNECTED) { doc["ip_address"] = WiFi.localIP().toString(); doc["gateway"] = WiFi.gatewayIP().toString(); doc["dns_servers"].add(WiFi.dnsIP().toString()); } String encoded; serializeJson(doc, encoded); if (encoded.length() < sizeof(wifiSnapshot)) { if (snapshotMutex) xSemaphoreTake(snapshotMutex, portMAX_DELAY); encoded.toCharArray(wifiSnapshot, sizeof(wifiSnapshot)); wifiReady = true; if (snapshotMutex) xSemaphoreGive(snapshotMutex); } WiFi.scanDelete(); logLine(String("WiFi 扫描完成：") + count + " 个"); }
void scanWorker(void*) { uint32_t last = millis(); for (;;) { if (configMode) { vTaskDelay(pdMS_TO_TICKS(100)); continue; } if (WiFi.status() == WL_CONNECTED && millis() - last >= config.interval * 1000UL) { scanBluetooth(config.interval * 500UL); scanWifi(config.interval * 500UL); ++scanGeneration; last = millis(); } vTaskDelay(pdMS_TO_TICKS(100)); } }

void sendData(const char* type, const char* json, uint64_t sequence, uint64_t timestamp) { if (!authenticated || !ws.isConnected()) return; DynamicJsonDocument message(16384); message["type"] = "environment_data"; message["version"] = 1; message["device_id"] = config.server.device; message["data_type"] = type; message["timestamp"] = timestamp; message["sequence"] = sequence; DynamicJsonDocument data(6144); if (deserializeJson(data, json) != DeserializationError::Ok) return; message["data"] = data.as<JsonObject>(); String payload; payload.reserve(16384); serializeJson(message, payload); bool sent = ws.sendTXT(payload); logLine(String("上传 ") + type + (sent ? " 已发送" : " 发送失败")); data.clear(); message.clear(); payload = String(); }
void sendSnapshot() { if (!authenticated || !ws.isConnected() || scanGeneration == uploadedGeneration) return; String ble, wifi; bool bReady, wReady; if (snapshotMutex) xSemaphoreTake(snapshotMutex, portMAX_DELAY); ble = bleSnapshot; wifi = wifiSnapshot; bReady = bleReady; wReady = wifiReady; if (snapshotMutex) xSemaphoreGive(snapshotMutex); if (!bReady) ble = "{\"devices\":[]}"; if (!wReady) wifi = "{\"networks\":[]}"; uint64_t now = epochMs(); if (!now) return; sendData("bluetooth", ble.c_str(), nextSequence(bleSequence, "bluetooth", now), now); ble = String(); yield(); sendData("wifi", wifi.c_str(), nextSequence(wifiSequence, "wifi", now), now); wifi = String(); uploadedGeneration = scanGeneration; }
void sendAuth() { StaticJsonDocument<512> message; message["type"] = "auth"; message["role"] = "collector"; message["token"] = config.server.token; message["device_id"] = config.server.device; JsonObject device = message["device"].to<JsonObject>(); device["name"] = "ESP32-C3 WiFi/Bluetooth Collector"; device["device_type"] = "esp32-c3"; JsonArray capabilities = device["capabilities"].to<JsonArray>(); capabilities.add("wifi"); capabilities.add("bluetooth"); String payload; serializeJson(message, payload); ws.sendTXT(payload); logLine("发送 WebSocket 认证"); }
void onWsEvent(WStype_t event, uint8_t* payload, size_t length) { if (event == WStype_CONNECTED) { authenticated = false; wsConnectedAt = millis(); lastPingAt = millis(); wsBackoffMs = kWsRetryStartMs; sendAuth(); logLine("WebSocket 已连接，发送认证"); } else if (event == WStype_DISCONNECTED) { authenticated = false; wsStarted = false; nextWsAt = millis() + wsBackoffMs; logLine(String("WebSocket 已断开，") + wsBackoffMs / 1000 + " 秒后重连"); wsBackoffMs = min<uint32_t>(wsBackoffMs * 2, kWsRetryMaxMs); } else if (event == WStype_ERROR) logLine("WebSocket 库报告连接错误"); else if (event == WStype_TEXT) { StaticJsonDocument<1024> message; if (deserializeJson(message, payload, length) != DeserializationError::Ok) return; const char* type = message["type"] | ""; if (!strcmp(type, "auth_result")) { authenticated = message["success"] | false; if (authenticated) { wsBackoffMs = kWsRetryStartMs; logLine("WebSocket 认证成功"); } else logLine("WebSocket 认证失败"); } else if (!strcmp(type, "ping")) ws.sendTXT("{\"type\":\"ping\"}"); else if (!strcmp(type, "data_result")) logLine(String("服务器确认 ") + (message["data_type"] | "unknown")); } }

void ledMaintain() { static uint32_t nextFlash = 0; static bool pulse = false; uint32_t now = millis(); if (configMode || WiFi.status() != WL_CONNECTED || !ws.isConnected() || !authenticated) { digitalWrite(kLedPin, LOW); pulse = false; return; } if (now - nextFlash >= 3000) { digitalWrite(kLedPin, LOW); pulse = true; nextFlash = now; } else if (pulse && now - nextFlash >= 100) { digitalWrite(kLedPin, HIGH); pulse = false; } }
void buttonMaintain() { static bool last = HIGH; static uint32_t changed = 0; bool state = digitalRead(kBootPin); uint32_t now = millis(); if (state != last) { last = state; changed = now; logLine(state == LOW ? "BOOT 按钮按下，GPIO9" : "BOOT 按钮释放，GPIO9"); } if (state == LOW && now - changed >= 40) startConfigMode(); }
void sendLoginPage(const String& error = "") { String page; page.reserve(3000); page += F("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>RemoteEnv 管理登录</title><style>body{font-family:system-ui;background:#eef2f5;margin:0;padding:28px;color:#17202a}main{max-width:460px;margin:auto;background:#fff;padding:28px;border-radius:16px;box-shadow:0 8px 28px #0002}h1{margin-top:0}label{display:block;margin-top:18px;font-weight:600}input{box-sizing:border-box;width:100%;padding:12px;margin-top:7px;border:1px solid #bcc7d0;border-radius:8px;font-size:16px}button{width:100%;padding:12px;margin-top:24px;border:0;border-radius:8px;background:#1769aa;color:#fff;font-size:16px}.error{color:#b42318}</style></head><body><main><h1>RemoteEnv 管理登录</h1><p>登录后进入采集器配置面板。</p>"); if (error.length()) { page += F("<p class='error'>"); page += escapeHtml(error.c_str()); page += F("</p>"); } page += F("<form method='post' action='/login'><label>管理员密码<input name='password' type='password' required autofocus></label><button type='submit'>登录并进入配置</button></form></main></body></html>"); headers(); web.send(200, "text/html; charset=utf-8", page); }
void setupPasswordPage() { String page = "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>首次配置</title><style>body{font-family:system-ui;background:#eef2f5;margin:0;padding:28px}main{max-width:540px;margin:auto;background:#fff;padding:28px;border-radius:16px;box-shadow:0 8px 28px #0002}label{display:block;margin-top:16px;font-weight:600}input{box-sizing:border-box;width:100%;padding:12px;margin-top:6px;border:1px solid #bcc7d0;border-radius:8px}button{width:100%;padding:12px;margin-top:24px;border:0;border-radius:8px;background:#1769aa;color:#fff}</style></head><body><main><h1>首次配置管理员密码</h1><p><b>必须先设置管理员密码。</b></p><p>管理员密码用于保护 WiFi、服务器 Token、设备 ID 和运行面板。设置成功后才能继续配置采集器。</p><form method='post' action='/setup-password'><label>管理员密码<input name='password' type='password' minlength='8' maxlength='96' required autofocus></label><label>确认管理员密码<input name='confirm' type='password' minlength='8' maxlength='96' required></label><button type='submit'>设置密码并继续</button></form></main></body></html>"; headers(); web.send(200, "text/html; charset=utf-8", page); }
void configPage() { touchConfig(); if (!hasPassword()) { setupPasswordPage(); return; } if (!requireLogin()) return; String page; page.reserve(11000); page += F("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>RemoteEnv 配置面板</title><style>body{font-family:system-ui,sans-serif;background:#eef2f5;margin:0;padding:24px;color:#17202a}main{max-width:760px;margin:auto;background:#fff;padding:26px;border-radius:16px;box-shadow:0 8px 28px #0002}h1{margin-top:0}h2{margin-top:28px;border-bottom:1px solid #dce3e8;padding-bottom:8px}fieldset{margin:12px 0;padding:14px;border:1px solid #d7e0e6;border-radius:10px}label{display:block;margin-top:10px;font-weight:600}input{box-sizing:border-box;width:100%;padding:10px;margin-top:5px;border:1px solid #bcc7d0;border-radius:8px;font-size:15px}button{padding:11px 16px;border:0;border-radius:8px;background:#1769aa;color:#fff;font-size:15px;cursor:pointer}.secondary{background:#68737d}p{color:#5d6872;line-height:1.5}.hint{background:#f0f7ff;border-left:4px solid #1769aa;padding:12px}.actions{margin-top:26px}</style></head><body><main><h1>ESP32-C3 环境采集器配置</h1><p class='hint'>配置模式五分钟无操作后自动重启回到正常模式。WiFi 按顺序连接，整轮失败后指数退避，最大 60 秒。</p><form method='post' action='/save'><h2>WiFi 列表（最多 5 个）</h2>"); for (uint8_t i = 0; i < kMaxWifi; ++i) { page += F("<fieldset><b>WiFi "); page += i + 1; page += F("</b><label>名称<input name='ssid"); page += i; page += F("' maxlength='63' value='"); page += escapeHtml(config.wifi[i].ssid).c_str(); page += F("'></label><label>密码<input name='password"); page += i; page += F("' type='password' maxlength='63' value='"); page += escapeHtml(config.wifi[i].password).c_str(); page += F("'></label></fieldset>"); } page += F("<h2>服务器（单服务器稳定模式）</h2><label>WebSocket 地址<input name='ws' maxlength='159' required value='"); page += escapeHtml(config.server.ws).c_str(); page += F("' placeholder='ws://host:8000/ws 或 wss://host/ws'></label><label>Token<input name='token' maxlength='159' required value='"); page += escapeHtml(config.server.token).c_str(); page += F("'></label><label>设备 ID<input name='device' maxlength='63' required value='"); page += escapeHtml(config.server.device).c_str(); page += F("'></label><label>采集间隔（秒，10-30）<input name='interval' type='number' min='10' max='30' required value='"); page += config.interval; page += F("'></label><div class='actions'><button type='submit'>保存配置并重启</button></div></form><p><a href='/panel'>打开运行面板</a>　<form method='post' action='/logout' style='display:inline'><button class='secondary' type='submit'>退出登录</button></form></p></main></body></html>"); headers(); web.send(200, "text/html; charset=utf-8", page); }
void panelPage() { if (!requireLogin()) return; String page; page.reserve(5000); page += F("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><meta http-equiv='refresh' content='10'><title>RemoteEnv 运行面板</title><style>body{font-family:system-ui;background:#eef2f5;margin:0;padding:24px}main{max-width:760px;margin:auto;background:#fff;padding:26px;border-radius:16px;box-shadow:0 8px 28px #0002}pre{white-space:pre-wrap;background:#101820;color:#d8f3dc;padding:16px;border-radius:10px;min-height:220px}a{color:#1769aa}</style></head><body><main><h1>ESP32-C3 运行面板</h1><p>WiFi："); page += WiFi.status() == WL_CONNECTED ? F("已连接 ") : F("未连接 "); page += WiFi.localIP().toString(); page += F("<br>WebSocket："); page += authenticated && ws.isConnected() ? F("已认证") : F("未连接或未认证"); page += F("<br>服务器设备 ID："); page += escapeHtml(config.server.device).c_str(); page += F("<br>BOOT 按钮：GPIO9　板载蓝灯：GPIO8（LOW=亮，HIGH=灭）</p><h2>最近日志</h2><pre>"); for (uint8_t i = 0; i < logCount; ++i) { page += escapeHtml(logs[i]).c_str(); page += '\n'; } page += F("</pre><p><a href='/'>返回配置面板</a></p></main></body></html>"); headers(); web.send(200, "text/html; charset=utf-8", page); }
void handleLogin() { if (!hasPassword()) { web.sendHeader("Location", "/setup-password", true); web.send(302, "text/plain", "请先设置管理员密码"); return; } if (!web.hasArg("password") || !constantEquals(config.passwordHash, passwordHash(web.arg("password")))) { sendLoginPage("管理员密码错误"); return; } createSession(); headers(); web.sendHeader("Set-Cookie", String("REMOTENV_SESSION=") + session + "; Max-Age=1800; HttpOnly; SameSite=Strict; Path=/", true); web.sendHeader("Location", "/", true); web.send(302, "text/plain", "登录成功"); }
void handleSetupPasswordPost() { if (hasPassword()) { if (!requireLogin()) return; web.send(409, "text/plain", "管理员密码已经设置"); return; } String password = web.arg("password"); if (password.length() < 8 || password.length() > 96 || password != web.arg("confirm")) { setupPasswordPage(); return; } copyText(config.passwordHash, sizeof(config.passwordHash), passwordHash(password)); saveConfig(); createSession(); headers(); web.sendHeader("Set-Cookie", String("REMOTENV_SESSION=") + session + "; Max-Age=1800; HttpOnly; SameSite=Strict; Path=/", true); web.sendHeader("Location", "/", true); web.send(302, "text/plain", "密码已设置"); }
void handleLogout() { session = ""; headers(); web.sendHeader("Set-Cookie", "REMOTENV_SESSION=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/", true); web.sendHeader("Location", "/login", true); web.send(302, "text/plain", "已退出"); }
void handleSave() { touchConfig(); if (!requireLogin()) return; Config next = config; uint8_t n = 0; for (uint8_t i = 0; i < kMaxWifi; ++i) { String ssid = web.arg(String("ssid") + i); if (!ssid.length()) continue; copyText(next.wifi[n].ssid, sizeof(next.wifi[n].ssid), ssid); copyText(next.wifi[n].password, sizeof(next.wifi[n].password), web.arg(String("password") + i)); ++n; } String host, path; uint16_t port; bool secure; String wsUrl = web.arg("ws"); if (!n || !parseWs(wsUrl.c_str(), host, port, path, secure) || !web.arg("token").length() || !web.arg("device").length()) { web.send(400, "text/plain; charset=utf-8", "至少配置一个 WiFi，且服务器地址、Token、设备 ID 必须完整"); return; } copyText(next.wsUrl, sizeof(next.wsUrl), wsUrl); copyText(next.token, sizeof(next.token), web.arg("token")); copyText(next.deviceId, sizeof(next.deviceId), web.arg("device")); long interval = web.arg("interval").toInt(); if (interval < 10 || interval > 30) { web.send(400, "text/plain; charset=utf-8", "采集间隔必须是 10 到 30 秒"); return; } next.interval = interval; config = next; saveConfig(); session = ""; headers(); web.send(200, "text/html; charset=utf-8", "<meta charset='utf-8'><p>配置已保存，设备将在短暂延迟后重启。</p>"); delay(500); ESP.restart(); }
void registerRoutes() { if (webRoutesRegistered) return; webRoutesRegistered = true; const char* keys[] = {"Cookie"}; web.collectHeaders(keys, 1); web.on("/", HTTP_GET, configPage); web.on("/login", HTTP_GET, [](){ sendLoginPage(); }); web.on("/login", HTTP_POST, handleLogin); web.on("/setup-password", HTTP_GET, setupPasswordPage); web.on("/setup-password", HTTP_POST, handleSetupPasswordPost); web.on("/logout", HTTP_POST, handleLogout); web.on("/panel", HTTP_GET, panelPage); web.on("/save", HTTP_POST, handleSave); web.onNotFound([](){ web.send(404, "text/plain", "Not found"); }); }
void startConfigMode() { if (configMode) return; configMode = true; configStartedAt = millis(); lastConfigActivityAt = configStartedAt; authenticated = false; ws.disconnect(); wsStarted = false; digitalWrite(kLedPin, LOW); WiFi.disconnect(true); WiFi.mode(WIFI_AP); String name = String("RemoteEnv-Setup-") + chipId(); WiFi.softAP(name.c_str(), kApPassword); registerRoutes(); if (!webServerStarted) { web.begin(); webServerStarted = true; } logLine(String("配置 AP：") + name + "，访问 http://" + WiFi.softAPIP().toString() + "/"); }
void beginWifi() { WiFi.mode(WIFI_STA); WiFi.begin(config.wifi[wifiIndex].ssid, config.wifi[wifiIndex].password); wifiAttemptAt = millis(); wifiConnecting = true; logLine(String("尝试连接 WiFi ") + (wifiIndex + 1) + "：" + config.wifi[wifiIndex].ssid); }
void maintainWifi() { uint32_t now = millis(); if (WiFi.status() == WL_CONNECTED) { if (wifiConnecting) { wifiConnecting = false; wifiBackoffMs = kWifiBackoffStartMs; wifiIndex = 0; wifiRound = 0; nextWsAt = now; logLine(String("WiFi 已连接：") + WiFi.localIP().toString()); setenv("TZ", "CST-8", 1); tzset(); configTime(0, 0, "ntp1.aliyun.com", "pool.ntp.org", "time.nist.gov"); if (!webServerStarted) { registerRoutes(); web.begin(); webServerStarted = true; } } return; } authenticated = false; if (wsStarted) { ws.disconnect(); wsStarted = false; } if (wifiConnecting && now - wifiAttemptAt < kWifiAttemptMs) return; if (wifiConnecting) { wifiConnecting = false; WiFi.disconnect(); ++wifiIndex; if (wifiIndex >= wifiCount()) { wifiIndex = 0; ++wifiRound; nextWifiAt = now + wifiBackoffMs; logLine(String("WiFi 第 ") + wifiRound + " 轮失败，" + wifiBackoffMs / 1000 + " 秒后重试"); wifiBackoffMs = min<uint32_t>(wifiBackoffMs * 2, kWifiBackoffMaxMs); } else nextWifiAt = now + 250; } if (static_cast<int32_t>(now - nextWifiAt) >= 0) { nextWifiAt = UINT32_MAX; beginWifi(); } }
void maintainWs() { uint32_t now = millis(); if (ws.isConnected() && !authenticated && wsConnectedAt && now - wsConnectedAt >= kAuthTimeoutMs) { logLine("WebSocket 认证超时，主动断开"); ws.disconnect(); wsStarted = false; nextWsAt = now + wsBackoffMs; } if (!wsStarted && static_cast<int32_t>(now - nextWsAt) >= 0) { String host, path; uint16_t port; bool secure; if (parseWs(config.wsUrl, host, port, path, secure)) { if (secure) ws.beginSSL(host.c_str(), port, path.c_str(), nullptr, "arduino"); else ws.begin(host.c_str(), port, path.c_str(), "arduino"); ws.onEvent(onWsEvent); ws.setReconnectInterval(wsBackoffMs); ws.enableHeartbeat(30000, 5000, 2); wsStarted = true; logLine("开始 WebSocket 稳定重连"); } else nextWsAt = now + wsBackoffMs; } if (authenticated && ws.isConnected() && now - lastPingAt >= kPingIntervalMs) { ws.sendTXT("{\"type\":\"ping\"}"); lastPingAt = now; } }
}

void setup() { Serial.begin(115200); delay(100); Serial.println("RemoteEnv ESP32-C3 boot"); pinMode(kLedPin, OUTPUT); digitalWrite(kLedPin, LOW); pinMode(kBootPin, INPUT_PULLUP); Serial.println("BOOT button: GPIO9"); Serial.println("LED GPIO8 active-low: LOW=ON HIGH=OFF"); NimBLEDevice::init(""); loadConfig(); loadSequences(); snapshotMutex = xSemaphoreCreateMutex(); if (snapshotMutex) xTaskCreatePinnedToCore(scanWorker, "env-scan", 8192, nullptr, 1, &scanTaskHandle, 0); if (!hasConfig() || digitalRead(kBootPin) == LOW) { startConfigMode(); return; } beginWifi(); startLocalWebServer(); }
void loop() { ledMaintain(); buttonMaintain(); if (configMode) {
     web.handleClient();
     if (millis() - lastConfigActivityAt >= kConfigTimeoutMs) {
         logLine("配网模式五分钟无操作，重启进入正常模式");
         delay(100);
         ESP.restart();
     }
     delay(2);
     return;
 } web.handleClient(); maintainWifi(); if (WiFi.status() == WL_CONNECTED) { ws.loop(); maintainWs(); sendSnapshot(); } ledMaintain(); delay(2); }
