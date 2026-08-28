# RemoteEnv Client

ESP8266 Remote Environment Client：使用 ESP8266 SDK `wifi_send_pkt_freedom` 注入原始 802.11 Beacon Frame，连接 RemoteEnvServer 的 Consumer WebSocket，获取可见采集设备列表，按每页最多 5 个设备显示，并选择一个设备订阅其 `wifi` 数据。

## 与 Collector 的差异

- 配网、管理密码、登录、AP 超时、重连和日志页面沿用采集端架构。
- 不配置设备 ID；认证使用 Consumer Token，首帧角色为 `consumer`。
- 选择结果保存到 EEPROM，重启后自动恢复订阅。
- Beacon 帧由 `src/main/BeaconSimulator.cpp` 构造，包含 SSID、BSSID、Beacon Interval、Capability、Supported Rates 和 DS Parameter Set；RSSI 只保存并显示，不写入 Beacon。
- 单射频采用 Channel dwell 调度：同一信道连续发送多个 Beacon，约 2.5 秒后切换到下一信道；发送和切换均基于 `millis()`。
- `experiments/beacon_minimal` 是固定 `RemoteTest` / BSSID / Channel 1 的独立实验。

## 构建

使用 Arduino IDE 或 Arduino CLI，开发板选择 `NodeMCU 1.0 (ESP-12E Module)`。依赖与 Collector 一致：ESP8266 core、WebSockets 2.4.1+、ArduinoJson 7.4.2+ 和 Crypto。

```powershell
arduino-cli compile --fqbn esp8266:esp8266:nodemcuv2 src/main
```

