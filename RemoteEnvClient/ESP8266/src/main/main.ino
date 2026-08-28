#include <Arduino.h>
#include <ArduinoJson.h>
#include <Crypto.h>
#include <EEPROM.h>
#include <ESP8266WebServer.h>
#include <ESP8266WiFi.h>
#include <WebSocketsClient.h>
#include "BeaconSimulator.h"
#include <sys/time.h>
#include <time.h>

namespace {
constexpr uint8_t kLedPin = LED_BUILTIN;
constexpr uint8_t kConfigButtonPin = 0;  // GPIO0, active low
constexpr size_t kEepromSize = 640;
constexpr uint32_t kConfigMagic = 0x52454333;

constexpr size_t kPasswordHashLength = 64;
constexpr size_t kSessionTokenLength = 32;
constexpr uint32_t kSessionTimeoutMs = 1800000;
constexpr uint32_t kWifiConnectTimeoutMs = 15000;
constexpr uint32_t kAuthTimeoutMs = 15000;
constexpr uint32_t kApplicationPingIntervalMs = 10000;
constexpr uint32_t kConfigModeTimeoutMs = 300000;
constexpr uint32_t kWifiRetryIntervalMs = 5000;
constexpr uint32_t kWebSocketRetryIntervalMs = 5000;
constexpr uint8_t kLogCapacity = 10;
constexpr uint8_t kLogLineLength = 96;
constexpr time_t kMinimumValidEpoch = 1700000000;
constexpr char kApPassword[] = "12345678";

struct DeviceConfig {
    char wifiSsid[64];
    char wifiPassword[64];
    char wsUrl[160];
    char token[160];
    char selectedDeviceId[65];
    char passwordHash[65];

};

struct StoredConfig {
    uint32_t magic;
    DeviceConfig config;
};

DeviceConfig config;
WebSocketsClient websocket;
ESP8266WebServer webServer(80);
BeaconSimulator beaconSimulator;
constexpr uint8_t kMaxRemoteDevices = 48;
constexpr uint8_t kDevicesPerPage = 5;
struct RemoteDevice {
    char deviceId[65];
    char name[65];
    bool online;
    uint8_t wifiCount;
};
RemoteDevice remoteDevices[kMaxRemoteDevices]{};
BeaconNetwork wifiSnapshotBuffer[24]{};
uint8_t remoteDeviceCount = 0;
int8_t devicePage = 0;
int8_t selectedDeviceIndex = -1;
char runtimeSelectedDeviceId[65] = "";
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
uint32_t nextRefreshAt = 0;

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
    const String salted = String(ESP.getChipId(), HEX) + ":" + password;
    return experimental::crypto::SHA256::hash(salted);
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
        const uint8_t value = static_cast<uint8_t>(ESP.random());
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
    return (start == 0 || cookie[start - 1] == ' ' || cookie[start - 1] == ';') &&
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
           config.token[0] != '\0';
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
    if (legacyConfig || stored.magic == 0x52454332 || stored.magic == kConfigMagic) {
        config = stored.config;
        if (legacyConfig) {
            memset(config.passwordHash, 0, sizeof(config.passwordHash));
        }

        config.wifiSsid[sizeof(config.wifiSsid) - 1] = '\0';
        config.wifiPassword[sizeof(config.wifiPassword) - 1] = '\0';
        config.wsUrl[sizeof(config.wsUrl) - 1] = '\0';
        config.token[sizeof(config.token) - 1] = '\0';
        config.selectedDeviceId[sizeof(config.selectedDeviceId) - 1] = '\0';
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
    message["role"] = "consumer";
    message["token"] = config.token;
    JsonObject device = message["device"].to<JsonObject>();
    device["name"] = "ESP8266 Remote Environment Client";
    device["device_type"] = "esp8266";
    JsonArray capabilities = device["capabilities"].to<JsonArray>();
    capabilities.add("wifi_beacon");

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

void sendSubscribe(const char* deviceId) {
    StaticJsonDocument<256> message;
    message["type"] = "subscribe";
    message["device_id"] = deviceId;
    JsonArray types = message["data_types"].to<JsonArray>();
    types.add("wifi");
    String payload;
    serializeJson(message, payload);
    websocket.sendTXT(payload);
}

void sendRefresh(const char* deviceId) {
    if (!deviceId || deviceId[0] == '\0' || !websocket.isConnected() || !authenticated) return;
    StaticJsonDocument<256> message;
    message["type"] = "refresh";
    message["device_id"] = deviceId;
    JsonArray types = message["data_types"].to<JsonArray>();
    types.add("wifi");
    String payload;
    serializeJson(message, payload);
    websocket.sendTXT(payload);
    blinkConnected();
}

void parseDeviceList(JsonArrayConst devices) {
    char previousSelection[sizeof(runtimeSelectedDeviceId)]{};
    copyField(previousSelection, sizeof(previousSelection), String(runtimeSelectedDeviceId));
    remoteDeviceCount = 0;
    selectedDeviceIndex = -1;
    for (JsonObjectConst item : devices) {
        if (remoteDeviceCount >= kMaxRemoteDevices) break;
        RemoteDevice& device = remoteDevices[remoteDeviceCount++];
        memset(&device, 0, sizeof(device));
        copyField(device.deviceId, sizeof(device.deviceId), String(item["device_id"] | ""));
        copyField(device.name, sizeof(device.name), String(item["name"] | device.deviceId));
        device.online = item["online"] | false;
    }
    for (uint8_t i = 1; i < remoteDeviceCount; ++i) {
        RemoteDevice current = remoteDevices[i];
        int8_t position = static_cast<int8_t>(i) - 1;
        while (position >= 0 && current.online && !remoteDevices[position].online) {
            remoteDevices[position + 1] = remoteDevices[position];
            --position;
        }
        remoteDevices[position + 1] = current;
    }
    const char* selection = previousSelection[0] != '\0' ? previousSelection : config.selectedDeviceId;
    if (selection[0] != '\0') {
        for (uint8_t i = 0; i < remoteDeviceCount; ++i) {
            if (strcmp(remoteDevices[i].deviceId, selection) == 0) {
                selectedDeviceIndex = i;
                copyField(runtimeSelectedDeviceId, sizeof(runtimeSelectedDeviceId), String(selection));
                sendSubscribe(runtimeSelectedDeviceId);
                break;
            }
        }
    }
    addLog(String("设备列表更新：") + remoteDeviceCount + " 个");
}

void updateWifiSnapshot(JsonObjectConst envelope) {
    if (strcmp(envelope["data_type"] | "", "wifi") != 0) return;
    JsonArrayConst source = envelope["data"]["networks"].as<JsonArrayConst>();
    if (source.isNull()) {
        addLog("WiFi 数据缺少 data.networks");
        return;
    }
    const char* deviceId = envelope["device_id"] | "";
    for (uint8_t i = 0; i < remoteDeviceCount; ++i) {
        if (strcmp(remoteDevices[i].deviceId, deviceId) != 0) continue;
        uint8_t count = 0;
        for (JsonObjectConst item : source) {
            if (count >= 24) break;
            memset(&wifiSnapshotBuffer[count], 0, sizeof(wifiSnapshotBuffer[count]));
            copyField(wifiSnapshotBuffer[count].ssid, sizeof(wifiSnapshotBuffer[count].ssid), String(item["ssid"] | ""));
            const String bssid = item["bssid"] | "";
            String normalized = bssid;
            normalized.replace(":", "");
            if (normalized.length() != 12) continue;
            for (uint8_t octet = 0; octet < 6; ++octet) {
                wifiSnapshotBuffer[count].bssid[octet] = static_cast<uint8_t>(strtoul(normalized.substring(octet * 2, octet * 2 + 2).c_str(), nullptr, 16));
            }
            wifiSnapshotBuffer[count].channel = WiFi.status() == WL_CONNECTED ? WiFi.channel() : 1;
            wifiSnapshotBuffer[count].rssi = item["rssi"] | -80;
            wifiSnapshotBuffer[count].encryption = item["encryption"] | 0;
            ++count;
        }
        remoteDevices[i].wifiCount = count;
        if (i == selectedDeviceIndex) beaconSimulator.setNetworks(wifiSnapshotBuffer, count);
        addLog(String("收到 WiFi 数据：") + deviceId + "，" + count + " 个");
        return;
    }
    addLog(String("收到 WiFi 数据但设备未匹配：") + deviceId);
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
            JsonDocument message;
            const DeserializationError parseError = deserializeJson(message, payload, length);
            if (parseError != DeserializationError::Ok) {
                addLog(String("收到无效的服务端 JSON：") + parseError.c_str() + "，长度=" + length);
                break;
            }
            const char* messageType = message["type"] | "";
            if (strcmp(messageType, "auth_result") == 0) {
                authenticated = message["success"] | false;
                addLog(authenticated ? "WebSocket 认证成功" : "WebSocket 认证失败");
            } else if (strcmp(messageType, "device_list") == 0) {
                parseDeviceList(message["devices"].as<JsonArrayConst>());
            } else if (strcmp(messageType, "environment_data") == 0) {
                updateWifiSnapshot(message.as<JsonObjectConst>());
            } else if (strcmp(messageType, "pong") == 0) {
                addLog("收到服务端 Pong");
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

const char kConfigPage[] PROGMEM = R"HTML(<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RemoteEnv 配置</title><style>body{font-family:system-ui,sans-serif;background:#f3f5f7;margin:0;padding:24px;color:#17202a}main{max-width:520px;margin:auto;background:white;padding:24px;border-radius:12px;box-shadow:0 4px 18px #0002}h1{font-size:22px}label{display:block;margin-top:16px;font-weight:600}input{box-sizing:border-box;width:100%;padding:11px;margin-top:6px;border:1px solid #bbc4cc;border-radius:7px;font-size:15px}button{width:100%;margin-top:24px;padding:12px;border:0;border-radius:7px;background:#1769aa;color:white;font-size:16px}p{color:#5d6872;font-size:14px;line-height:1.5}</style></head><body><main><h1>ESP8266 环境采集器配置</h1><p>保存后设备会自动重启。WS 地址请输入完整格式，例如 wss://10.0.0.10:8000/ws。</p><form method="post" action="/save"><label>WiFi 名称<input name="ssid" maxlength="63" required></label><label>WiFi 密码<input name="password" type="password" maxlength="63"></label><label>WS 地址<input name="ws" maxlength="159" required></label><label>Token<input name="token" maxlength="159" required></label><label>设备 ID<input name="device" maxlength="63" required></label><button type="submit">保存并重启</button></form></main></body></html>)HTML";

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
    page += F("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>RemoteEnv 登录</title><style>body{font-family:system-ui,sans-serif;background:#f3f5f7;margin:0;padding:24px;color:#17202a}main{max-width:460px;margin:auto;background:white;padding:24px;border-radius:12px;box-shadow:0 4px 18px #0002}label{display:block;margin-top:16px;font-weight:600}input{box-sizing:border-box;width:100%;padding:11px;margin-top:6px;border:1px solid #bbc4cc;border-radius:7px;font-size:15px}button{width:100%;margin-top:24px;padding:12px;border:0;border-radius:7px;background:#1769aa;color:white;font-size:16px}.error{color:#b42318}</style></head><body><main><h1>ESP8266 管理登录</h1>");
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
    webServer.sendHeader("Location", "/config", true);
    webServer.send(302, "text/plain", "登录成功");
}

void handleConfigPage();
void startWebSocket();

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
    page += F("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>RemoteEnv 配置</title><style>body{font-family:system-ui,sans-serif;background:#f3f5f7;margin:0;padding:24px;color:#17202a}main{max-width:560px;margin:auto;background:white;padding:24px;border-radius:12px;box-shadow:0 4px 18px #0002}h1{font-size:22px}label{display:block;margin-top:16px;font-weight:600}input{box-sizing:border-box;width:100%;padding:11px;margin-top:6px;border:1px solid #bbc4cc;border-radius:7px;font-size:15px}button{width:100%;margin-top:24px;padding:12px;border:0;border-radius:7px;background:#1769aa;color:white;font-size:16px}a{color:#1769aa}p{color:#5d6872;font-size:14px;line-height:1.5}</style></head><body><main><h1>ESP8266 环境采集器配置</h1><p>保存后设备会自动重启。WS 地址支持 ws:// 和 wss://。</p><form method='post' action='/save'>");
    page += F("<label>WiFi 名称<input name='ssid' maxlength='63' required value='"); page += htmlEscape(config.wifiSsid); page += F("'></label>");
    page += F("<label>WiFi 密码<input name='password' type='password' maxlength='63' value='"); page += htmlEscape(config.wifiPassword); page += F("'></label>");
    page += F("<label>WS 地址<input name='ws' maxlength='159' required value='"); page += htmlEscape(config.wsUrl); page += F("'></label><p>所有远程 WiFi 均忽略服务端信道信息，统一在当前管理 WiFi 信道上模拟 SSID 和 BSSID。设备保持联网并每 3 秒请求最新数据。</p>");
    page += F("<label>Consumer Token<input name='token' maxlength='159' required value='"); page += htmlEscape(config.token); page += F("'></label><label>新管理密码<input name='newPassword' type='password' minlength='8' maxlength='96' placeholder='留空则保持不变'></label><label>确认新管理密码<input name='confirmPassword' type='password' minlength='8' maxlength='96' placeholder='留空则保持不变'></label><button type='submit'>应用配置并重启</button></form><p><a href='/devices'>打开设备选择</a> · <a href='/panel'>打开运行面板</a> · <form method='post' action='/logout' style='display:inline'><button type='submit' style='width:auto;margin:0;padding:4px 10px;background:#68737d'>退出登录</button></form></p></main></body></html>");
    webServer.send(200, "text/html; charset=utf-8", page);
}

void handleDevicesPage() {
    markConfigActivity();
    if (!hasAdminPassword()) {
        sendSecurityHeaders();
        webServer.sendHeader("Location", "/setup-password", true);
        webServer.send(302, "text/plain", "请先设置管理密码");
        return;
    }
    if (!requireSession()) return;
    String page;
    page.reserve(6200);
    page += F("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>RemoteEnv 设备选择</title><style>body{font-family:system-ui,sans-serif;background:#f3f5f7;margin:0;padding:24px;color:#17202a}main{max-width:680px;margin:auto;background:white;padding:24px;border-radius:12px;box-shadow:0 4px 18px #0002}h1{font-size:22px}section{border:1px solid #d7dde2;border-radius:8px;padding:14px;margin:10px 0}section.selected{border-color:#1769aa;background:#eef6fc}button{margin-top:10px;padding:10px 14px;border:0;border-radius:7px;background:#1769aa;color:white;font-size:14px}a{color:#1769aa}.online{color:#087f23}.offline{color:#68737d}.muted{color:#5d6872;font-size:14px}</style></head><body><main><h1>远程环境设备</h1>");
    if (remoteDeviceCount == 0) {
        page += F("<p class='muted'>当前没有可见设备。请确认 Consumer WebSocket 已认证，或服务端当前没有采集端。</p>");
    } else {
        uint8_t onlineCount = 0;
        for (uint8_t i = 0; i < remoteDeviceCount; ++i) if (remoteDevices[i].online) ++onlineCount;
        page += F("<p class='muted'>设备总数："); page += remoteDeviceCount; page += F(" · 在线："); page += onlineCount; page += F(" · 在线设备优先显示</p>");
        const uint8_t start = static_cast<uint8_t>(devicePage) * kDevicesPerPage;
        const uint8_t end = min<uint8_t>(start + kDevicesPerPage, remoteDeviceCount);
        for (uint8_t i = start; i < end; ++i) {
            page += i == selectedDeviceIndex ? F("<section class='selected'><b>") : F("<section><b>"); page += htmlEscape(remoteDevices[i].name); page += F("</b><br>");
            page += remoteDevices[i].online ? F("<span class='online'>在线</span>") : F("<span class='offline'>离线</span>");
            page += F(" · "); page += htmlEscape(remoteDevices[i].deviceId);
            page += F("<br>WiFi："); page += remoteDevices[i].wifiCount;
            if (i == selectedDeviceIndex) page += F("<br><b>当前模拟</b>");
            page += F("<form method='post' action='/select'><input type='hidden' name='device' value='"); page += htmlEscape(remoteDevices[i].deviceId); page += F("'><button type='submit'>立即选择并模拟</button></form></section>");
        }
        const int pages = (remoteDeviceCount + kDevicesPerPage - 1) / kDevicesPerPage;
        page += F("<p>第 "); page += devicePage + 1; page += F(" / "); page += pages; page += F(" 页</p><form method='post' action='/page'><button name='delta' value='-1'>上一页</button> <button name='delta' value='1'>下一页</button></form>");
    }
    page += F("<p><a href='/'>配置页</a> · <a href='/panel'>日志/状态页</a></p></main></body></html>");
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
    page.reserve(2200);
    page += F("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><meta http-equiv='refresh' content='5'><title>RemoteEnv 面板</title><style>body{font-family:system-ui,sans-serif;background:#f3f5f7;margin:0;padding:24px;color:#17202a}main{max-width:620px;margin:auto;background:white;padding:20px;border-radius:12px;box-shadow:0 4px 18px #0002}h1{font-size:22px}a{color:#1769aa}.log{white-space:pre-wrap;background:#101820;color:#d8f3dc;padding:10px;border-radius:8px;max-height:220px;overflow:hidden;font-size:12px}</style></head><body><main><h1>ESP8266 日志</h1>");
    page += F("<p>模式："); page += configMode ? F("配置 AP") : F("联网采集");
    page += F("<br>WiFi："); page += WiFi.status() == WL_CONNECTED ? F("已连接 ") : F("未连接 ");
    page += WiFi.localIP().toString();
    page += F("<br>WebSocket："); page += (authenticated && websocket.isConnected()) ? F("传输已连接，认证成功") : F("未连接或未认证");
    page += F("<br>当前模拟设备："); page += selectedDeviceIndex >= 0 ? htmlEscape(remoteDevices[selectedDeviceIndex].deviceId) : F("未选择");
    page += F("<br>Beacon："); page += beaconSimulator.running() ? F("运行中") : F("已停止");
    page += F("<br>Channel："); page += beaconSimulator.currentChannel();
    page += F("<br>SSID："); page += htmlEscape(beaconSimulator.currentSsid());
    page += F("</p><p><a href='/devices'>设备选择</a> · <a href='/config'>配置页面</a></p><h2>最近 10 条日志</h2><div class='log'>");
    const uint8_t first = 0;
    for (uint8_t i = first; i < logCount; ++i) { page += htmlEscape(String(logLines[i])); page += '\n'; }
    page += F("</div><p><a href='/logout'>退出登录</a></p></main></body></html>");
    webServer.send(200, "text/html; charset=utf-8", page);
}

void handleSelectDevice() {
    markConfigActivity();
    if (!requireSession() || !webServer.hasArg("device")) return;
    const String deviceId = webServer.arg("device");
    for (uint8_t i = 0; i < remoteDeviceCount; ++i) {
        if (deviceId != remoteDevices[i].deviceId) continue;
        selectedDeviceIndex = i;
        copyField(runtimeSelectedDeviceId, sizeof(runtimeSelectedDeviceId), deviceId);
        copyField(config.selectedDeviceId, sizeof(config.selectedDeviceId), deviceId);
        saveConfig();
        sendSubscribe(runtimeSelectedDeviceId);
        webServer.sendHeader("Location", "/devices", true);
        webServer.send(303, "text/plain; charset=utf-8", "设备已选择，等待 WiFi 数据");
        return;
    }
    webServer.send(404, "text/plain; charset=utf-8", "设备不存在");
}

void handleDevicePage() {
    markConfigActivity();
    if (!requireSession()) return;
    const int pages = (remoteDeviceCount + kDevicesPerPage - 1) / kDevicesPerPage;
    if (pages > 0) devicePage = constrain(devicePage + webServer.arg("delta").toInt(), 0, pages - 1);
    handleConfigPage();
}

void handleConnectTest() {
    markConfigActivity();
    if (!requireSession()) return;
    if (WiFi.status() != WL_CONNECTED) {
        webServer.send(503, "text/plain; charset=utf-8", "WiFi 尚未连接，无法连接 WebSocket");
        return;
    }
    nextWebSocketRetryAt = millis();
    startWebSocket();
    webServer.send(200, "text/plain; charset=utf-8", websocket.isConnected() ? "WebSocket 已连接" : "已触发 WebSocket 立即连接/重连，请查看日志");
}

void handleDataTest() {
    markConfigActivity();
    if (!requireSession()) return;
    if (!websocket.isConnected() || !authenticated) {
        webServer.send(503, "text/plain; charset=utf-8", "WebSocket 尚未认证，请先立即连接");
        return;
    }
    websocket.sendTXT("{\"type\":\"ping\"}");
    String result = String("已发送 Ping；设备数=") + remoteDeviceCount +
                    "，当前选择=" + (selectedDeviceIndex >= 0 ? remoteDevices[selectedDeviceIndex].deviceId : "无") +
                    "，Beacon=" + (beaconSimulator.running() ? "运行中" : "未运行");
    webServer.send(200, "text/plain; charset=utf-8", result);
}

void handleSaveConfig() {
    markConfigActivity();
    if (!hasAdminPassword()) {
        webServer.send(403, "text/plain; charset=utf-8", "请先设置管理密码");
        return;
    }
    if (!requireSession()) return;
    if (!webServer.hasArg("ssid") || !webServer.hasArg("password") ||
        !webServer.hasArg("ws") || !webServer.hasArg("token")) {
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
    webServer.collectHeaders("Cookie");
    webServer.on("/", HTTP_GET, handleConfigPage);
    webServer.on("/config", HTTP_GET, handleConfigPage);
    webServer.on("/devices", HTTP_GET, handleDevicesPage);
    webServer.on("/login", HTTP_GET, []() { sendLoginPage(); });
    webServer.on("/login", HTTP_POST, handleLogin);
    webServer.on("/setup-password", HTTP_GET, handleSetupPassword);
    webServer.on("/setup-password", HTTP_POST, handleSetupPasswordPost);
    webServer.on("/logout", HTTP_POST, handleLogout);
    webServer.on("/panel", HTTP_GET, handlePanel);
    webServer.on("/save", HTTP_POST, handleSaveConfig);
    webServer.on("/select", HTTP_POST, handleSelectDevice);
    webServer.on("/page", HTTP_POST, handleDevicePage);
    webServer.on("/connect", HTTP_POST, handleConnectTest);
    webServer.on("/data-test", HTTP_POST, handleDataTest);
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
    beaconSimulator.stop();
    configModeStartedAt = millis();
    lastConfigActivityAt = configModeStartedAt;
    authenticated = false;
    webSocketStarted = false;
    setLed(true);
    websocket.disconnect();
    WiFi.disconnect(true);
    WiFi.mode(WIFI_AP);
    const String apName = String("RemoteEnv-Setup-") + String(ESP.getChipId(), HEX);
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
    if (authenticated && websocket.isConnected() && selectedDeviceIndex >= 0 &&
        static_cast<int32_t>(now - nextRefreshAt) >= 0) {
        nextRefreshAt = now + 3000;
        sendRefresh(runtimeSelectedDeviceId);
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
    Serial.begin(115200);
    pinMode(kLedPin, OUTPUT);
    setLed(false);
    pinMode(kConfigButtonPin, INPUT_PULLUP);
    beaconSimulator.begin();
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
        beaconSimulator.loop();
    }
    delay(10);
}
