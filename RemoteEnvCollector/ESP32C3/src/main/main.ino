#include <Arduino.h>
#include <ArduinoJson.h>
#include <mbedtls/sha256.h>
#include <EEPROM.h>
#include <WebServer.h>
#include <NimBLEDevice.h>
#include <WiFi.h>
#include <WebSocketsClient.h>
#include <sys/time.h>
#include <time.h>

namespace {
constexpr uint8_t kLedPin = LED_BUILTIN;
constexpr uint8_t kConfigButtonPin = 0;  // GPIO0, active low
constexpr size_t kEepromSize = 640;
constexpr uint32_t kConfigMagic = 0x52454332;
constexpr size_t kPasswordHashLength = 64;
constexpr size_t kSessionTokenLength = 32;
constexpr uint32_t kSessionTimeoutMs = 1800000;
constexpr uint32_t kUploadIntervalMs = 3000;
constexpr uint32_t kWifiConnectTimeoutMs = 15000;
constexpr uint32_t kAuthTimeoutMs = 15000;
constexpr uint32_t kApplicationPingIntervalMs = 10000;
constexpr uint32_t kConfigModeTimeoutMs = 300000;
constexpr uint32_t kWifiRetryIntervalMs = 5000;
constexpr uint32_t kWebSocketRetryIntervalMs = 5000;
constexpr uint8_t kLogCapacity = 20;
constexpr uint8_t kLogLineLength = 96;
constexpr time_t kMinimumValidEpoch = 1700000000;
constexpr char kApPassword[] = "12345678";

struct DeviceConfig {
    char wifiSsid[64];
    char wifiPassword[64];
    char wsUrl[160];
    char token[160];
    char deviceId[64];
    char passwordHash[65];
};

struct StoredConfig {
    uint32_t magic;
    DeviceConfig config;
};

String getChipIdHex() {
    const uint64_t chipId = ESP.getEfuseMac();
    char value[17]{};
    snprintf(value, sizeof(value), "%04x%08x", static_cast<uint16_t>(chipId >> 32), static_cast<uint32_t>(chipId));
    return String(value);
}

DeviceConfig config;
WebSocketsClient websocket;
WebServer webServer(80);
uint32_t nextUploadAt = 0;
bool authenticated = false;
bool configMode = false;
bool lastButtonState = HIGH;
uint32_t lastButtonChangeAt = 0;
uint32_t connectedAt = 0;
uint32_t lastApplicationPingAt = 0;
char logLines[kLogCapacity][kLogLineLength];
uint8_t logCount = 0;
uint32_t configModeStartedAt = 0;
uint32_t lastConfigActivityAt = 0;
uint32_t wifiAttemptStartedAt = 0;
uint32_t nextWifiRetryAt = 0;
uint32_t nextWebSocketRetryAt = 0;
bool webServerStarted = false;
bool webRoutesRegistered = false;
bool wifiConnecting = false;
bool webSocketStarted = false;

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

bool hasConfig() {
    return config.wifiSsid[0] != '\0' && config.wsUrl[0] != '\0' &&
           config.token[0] != '\0' && config.deviceId[0] != '\0';
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
    if (legacyConfig || stored.magic == kConfigMagic) {
        config = stored.config;
        if (legacyConfig) {
            memset(config.passwordHash, 0, sizeof(config.passwordHash));
        }
        config.wifiSsid[sizeof(config.wifiSsid) - 1] = '\0';
        config.wifiPassword[sizeof(config.wifiPassword) - 1] = '\0';
        config.wsUrl[sizeof(config.wsUrl) - 1] = '\0';
        config.token[sizeof(config.token) - 1] = '\0';
        config.deviceId[sizeof(config.deviceId) - 1] = '\0';
        config.passwordHash[sizeof(config.passwordHash) - 1] = '\0';
    } else {
        memset(&config, 0, sizeof(config));
    }
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

void sendAuth() {
    StaticJsonDocument<512> message;
    message["type"] = "auth";
    message["role"] = "collector";
    message["token"] = config.token;
    message["device_id"] = config.deviceId;
    JsonObject device = message["device"].to<JsonObject>();
    device["name"] = "ESP32-C3 WiFi/Bluetooth Collector";
    device["device_type"] = "esp32-c3";
    JsonArray capabilities = device["capabilities"].to<JsonArray>();
    capabilities.add("wifi");
    capabilities.add("bluetooth");

    String payload;
    serializeJson(message, payload);
    websocket.sendTXT(payload);
    addLog("发送 WebSocket 认证");
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
    if (!authenticated || !websocket.isConnected()) {
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
uint64_t currentEpochMillis();
void blinkConnected();
String base64Encode(const uint8_t* data, size_t length);

void sendBluetoothData() {
    if (!authenticated || WiFi.status() != WL_CONNECTED || !websocket.isConnected()) return;
    const uint64_t epochMillis = currentEpochMillis();
    if (epochMillis == 0) return;

    NimBLEScan* scanner = NimBLEDevice::getScan();
    scanner->setActiveScan(true);
    scanner->setInterval(45);
    scanner->setWindow(15);
    NimBLEScanResults results = scanner->getResults(4, false);

    DynamicJsonDocument message(12288);
    message["type"] = "environment_data";
    message["version"] = 1;
    message["device_id"] = config.deviceId;
    message["data_type"] = "bluetooth";
    message["timestamp"] = epochMillis;
    message["sequence"] = epochMillis;
    JsonArray devices = message["data"]["devices"].to<JsonArray>();
    for (int i = 0; i < results.getCount(); ++i) {
        const NimBLEAdvertisedDevice* device = results.getDevice(i);
        JsonObject item = devices.add<JsonObject>();
        item["name"] = device->haveName() ? device->getName().c_str() : "";
        item["address"] = device->getAddress().toString().c_str();
        item["rssi"] = device->getRSSI();
        item["mode"] = "ble";
        if (device->haveTXPower()) item["txPower"] = device->getTXPower();
        if (device->haveServiceUUID()) {
            JsonArray uuids = item["serviceUuids"].to<JsonArray>();
            for (int j = 0; j < device->getServiceUUIDCount(); ++j) {
                uuids.add(device->getServiceUUID(j).toString().c_str());
            }
            if (device->getServiceUUIDCount() > 0) item["uuid"] = device->getServiceUUID(0).toString().c_str();
        }
        if (device->haveManufacturerData()) {
            JsonObject manufacturers = item["manufacturerData"].to<JsonObject>();
            const std::string raw = device->getManufacturerData();
            String hex;
            for (uint8_t byte : raw) {
                if (byte < 16) hex += '0';
                hex += String(byte, HEX);
            }
            manufacturers["0"] = hex;
            item["rawHex"] = hex;
            item["rawLength"] = raw.length();
            item["raw"] = base64Encode(reinterpret_cast<const uint8_t*>(raw.data()), raw.length());
        }
    }
    String payload;
    serializeJson(message, payload);
    const bool sent = websocket.sendTXT(payload);
    scanner->clearResults();
    if (sent && authenticated && websocket.isConnected()) {
        blinkConnected();
        addLog(String("上传 Bluetooth: ") + results.getCount() + " 个");
    } else {
        addLog("上传 Bluetooth 失败");
    }
}
void sendWifiData() {
    if (!authenticated || WiFi.status() != WL_CONNECTED) {
        return;
    }
    const uint64_t epochMillis = currentEpochMillis();
    if (epochMillis == 0) {
        addLog("等待北京时间 NTP 同步");
        return;
    }

    const int count = WiFi.scanNetworks(false, true);
    StaticJsonDocument<4096> message;
    message["type"] = "environment_data";
    message["version"] = 1;
    message["device_id"] = config.deviceId;
    message["data_type"] = "wifi";
    message["timestamp"] = epochMillis;
    message["sequence"] = epochMillis;
    JsonObject data = message["data"].to<JsonObject>();
    JsonArray networks = data["networks"].to<JsonArray>();
    for (int i = 0; i < count; ++i) {
        JsonObject network = networks.add<JsonObject>();
        network["ssid"] = WiFi.SSID(i);
        network["bssid"] = WiFi.BSSIDstr(i);
        network["rssi"] = WiFi.RSSI(i);
        network["channel"] = WiFi.channel(i);
        network["encryption"] = static_cast<int>(WiFi.encryptionType(i));
    }
    String payload;
    serializeJson(message, payload);
    const bool sent = websocket.sendTXT(payload);
    WiFi.scanDelete();
    if (sent && authenticated && websocket.isConnected()) {
        blinkConnected();
        addLog(String("上传 WiFi: ") + count + " 个，序号=" + epochMillis);
    } else {
        addLog("上传失败：WebSocket 未认证、已断开或发送失败");
    }
}

void onWebSocketEvent(WStype_t type, uint8_t* payload, size_t length) {
    switch (type) {
        case WStype_CONNECTED:
            authenticated = false;
            connectedAt = millis();
            lastApplicationPingAt = millis() + kApplicationPingIntervalMs;
            addLog("WebSocket 已连接，发送认证");
            sendAuth();
            break;
        case WStype_DISCONNECTED:
            authenticated = false;
            connectedAt = 0;
            webSocketStarted = false;
            nextWebSocketRetryAt = millis() + kWebSocketRetryIntervalMs;
            addLog("WebSocket 已断开，5 秒后无限重连");
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
                authenticated = message["success"] | false;
                addLog(authenticated ? "WebSocket 认证成功" : "WebSocket 认证失败");
            } else if (strcmp(messageType, "ping") == 0) {
                websocket.sendTXT("{\"type\":\"ping\"}");
                addLog("收到应用层 Ping，已回复");
            }
            break;
        }
        default:
            break;
    }
}

const char kConfigPage[] PROGMEM = R"HTML(<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RemoteEnv 配置</title><style>body{font-family:system-ui,sans-serif;background:#f3f5f7;margin:0;padding:24px;color:#17202a}main{max-width:520px;margin:auto;background:white;padding:24px;border-radius:12px;box-shadow:0 4px 18px #0002}h1{font-size:22px}label{display:block;margin-top:16px;font-weight:600}input{box-sizing:border-box;width:100%;padding:11px;margin-top:6px;border:1px solid #bbc4cc;border-radius:7px;font-size:15px}button{width:100%;margin-top:24px;padding:12px;border:0;border-radius:7px;background:#1769aa;color:white;font-size:16px}p{color:#5d6872;font-size:14px;line-height:1.5}</style></head><body><main><h1>ESP32-C3 环境采集器配置</h1><p>保存后设备会自动重启。WS 地址请输入完整格式，例如 wss://10.0.0.10:8000/ws。</p><form method="post" action="/save"><label>WiFi 名称<input name="ssid" maxlength="63" required></label><label>WiFi 密码<input name="password" type="password" maxlength="63"></label><label>WS 地址<input name="ws" maxlength="159" required></label><label>Token<input name="token" maxlength="159" required></label><label>设备 ID<input name="device" maxlength="63" required></label><button type="submit">保存并重启</button></form></main></body></html>)HTML";

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
    page += F("<label>WiFi 名称<input name='ssid' maxlength='63' required value='"); page += htmlEscape(config.wifiSsid); page += F("'></label>");
    page += F("<label>WiFi 密码<input name='password' type='password' maxlength='63' value='"); page += htmlEscape(config.wifiPassword); page += F("'></label>");
    page += F("<label>WS 地址<input name='ws' maxlength='159' required value='"); page += htmlEscape(config.wsUrl); page += F("'></label>");
    page += F("<label>Token<input name='token' maxlength='159' required value='"); page += htmlEscape(config.token); page += F("'></label>");
    page += F("<label>设备 ID<input name='device' maxlength='63' required value='"); page += htmlEscape(config.deviceId); page += F("'></label><label>新管理密码<input name='newPassword' type='password' minlength='8' maxlength='96' placeholder='留空则保持不变'></label><label>确认新管理密码<input name='confirmPassword' type='password' minlength='8' maxlength='96' placeholder='留空则保持不变'></label><button type='submit'>保存配置</button></form><p><a href='/panel'>打开运行面板</a> · <form method='post' action='/logout' style='display:inline'><button type='submit' style='width:auto;margin:0;padding:4px 10px;background:#68737d'>退出登录</button></form></p></main></body></html>");
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
    page += F("<br>WebSocket："); page += (authenticated && websocket.isConnected()) ? F("传输已连接，认证成功") : F("未连接或未认证");
    page += F("<br>设备 ID："); page += htmlEscape(config.deviceId);    page += F("</p><h2>最近日志</h2><pre>");
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
    if (!webServer.hasArg("ssid") || !webServer.hasArg("password") ||
        !webServer.hasArg("ws") || !webServer.hasArg("token") || !webServer.hasArg("device")) {
        webServer.send(400, "text/plain; charset=utf-8", "缺少配置字段");
        return;
    }
    String ws = webServer.arg("ws");
    String host, path;
    uint16_t port = 0;
    bool secure = false;
    if (!parseWsUrl(ws.c_str(), host, port, path, secure)) {
        webServer.send(400, "text/plain; charset=utf-8", "WS 地址必须以 ws:// 或 wss:// 开头，并包含有效主机名");
        return;
    }
    copyField(config.wifiSsid, sizeof(config.wifiSsid), webServer.arg("ssid"));
    copyField(config.wifiPassword, sizeof(config.wifiPassword), webServer.arg("password"));
    copyField(config.wsUrl, sizeof(config.wsUrl), ws);
    copyField(config.token, sizeof(config.token), webServer.arg("token"));
    copyField(config.deviceId, sizeof(config.deviceId), webServer.arg("device"));
    const String newPassword = webServer.arg("newPassword");
    const String confirmPassword = webServer.arg("confirmPassword");
    if (newPassword.length() > 0) {
        if (newPassword.length() < 8 || newPassword.length() > 96 || newPassword != confirmPassword) {
            webServer.send(400, "text/plain; charset=utf-8", "新管理密码无效或两次输入不一致");
            return;
        }
        copyField(config.passwordHash, sizeof(config.passwordHash), passwordDigest(newPassword));
    }
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
    authenticated = false;
    webSocketStarted = false;
    setLed(true);
    websocket.disconnect();
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
    WiFi.begin(config.wifiSsid, config.wifiPassword);
    wifiAttemptStartedAt = millis();
    wifiConnecting = true;
    addLog(String("尝试连接 WiFi：") + config.wifiSsid);
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
            nextWebSocketRetryAt = now;
        }
        return;
    }
    authenticated = false;
    if (WiFi.status() != WL_CONNECTED) {
        if (webSocketStarted) {
            websocket.disconnect();
            webSocketStarted = false;
        }
        if (wifiConnecting && now - wifiAttemptStartedAt < kWifiConnectTimeoutMs) return;
        if (wifiConnecting) {
            wifiConnecting = false;
            addLog("WiFi 连接失败，5 秒后无限重试");
            WiFi.disconnect();
        }
        if (static_cast<int32_t>(now - nextWifiRetryAt) >= 0) {
            nextWifiRetryAt = now + kWifiRetryIntervalMs;
            beginWifiAttempt();
        }
    }
}

void startWebSocket() {
    if (webSocketStarted || WiFi.status() != WL_CONNECTED) return;
    String host, path;
    uint16_t port = 0;
    bool secure = false;
    if (!parseWsUrl(config.wsUrl, host, port, path, secure)) {
        addLog("WS 地址无效，5 秒后继续重试");
        nextWebSocketRetryAt = millis() + kWebSocketRetryIntervalMs;
        return;
    }
    if (secure) {
        websocket.beginSSL(host.c_str(), port, path.c_str(), nullptr, "arduino");
    } else {
        websocket.begin(host.c_str(), port, path.c_str(), "arduino");
    }
    websocket.onEvent(onWebSocketEvent);
    websocket.setReconnectInterval(kWebSocketRetryIntervalMs);
    websocket.enableHeartbeat(15000, 3000, 2);
    webSocketStarted = true;
    addLog("开始 WebSocket 无限重试");
}

void maintainWebSocket() {
    const uint32_t now = millis();
    if (websocket.isConnected() && !authenticated && connectedAt != 0 &&
        now - connectedAt >= kAuthTimeoutMs) {
        addLog("WebSocket 认证超时，主动断开等待重连");
        websocket.disconnect();
        connectedAt = 0;
        webSocketStarted = false;
    }
    if (static_cast<int32_t>(now - nextWebSocketRetryAt) >= 0) {
        nextWebSocketRetryAt = now + kWebSocketRetryIntervalMs;
        startWebSocket();
    }
    if (authenticated && websocket.isConnected() &&
        now - lastApplicationPingAt >= kApplicationPingIntervalMs) {
        websocket.sendTXT("{\"type\":\"ping\"}");
        lastApplicationPingAt = now;
        addLog("发送应用层 Ping");
    }
}

void checkConfigButton() {
    const bool state = digitalRead(kConfigButtonPin);
    if (state != lastButtonState) {
        lastButtonState = state;
        lastButtonChangeAt = millis();
    }
    if (state == LOW && millis() - lastButtonChangeAt >= 40) {
        startConfigMode();
    }
}
}  // namespace

void setup() {
    NimBLEDevice::init("");
    Serial.begin(115200);
    pinMode(kLedPin, OUTPUT);
    setLed(false);
    pinMode(kConfigButtonPin, INPUT_PULLUP);
    loadConfig();

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
        websocket.loop();
        maintainWebSocket();
        const uint32_t now = millis();
        if (static_cast<int32_t>(now - nextUploadAt) >= 0) {
            nextUploadAt = now + kUploadIntervalMs;
            sendBluetoothData();
            sendWifiData();
        }
    }
    delay(10);
}
