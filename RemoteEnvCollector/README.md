# RemoteEnvCollect

ESP8266 Collector：扫描附近 WiFi，使用可配置的 WS/WSS 地址连接 RemoteEnvServer，并按 3 秒周期上传。

配套服务端：https://github.com/FairyXH/RemoteEnvServer

## 配网与运行状态

- 首次启动、没有有效配置或 GPIO0 被按下时进入配置 AP。
- 已有配置时，如果 WiFi 不在范围内、密码错误或连接发生任何失败，设备保持正常模式并无限重试，不会自动进入 AP。
- WebSocket 连接、认证、底层 Ping/Pong 或应用层心跳失败时，设备保持正常模式并无限重试。
- AP 名称为 `RemoteEnv-Setup-<chipid>`，默认密码为 `12345678`。
- 连接 AP 后访问 `http://192.168.4.1/`，填写 WiFi 名称、WiFi 密码、完整 WS 地址、Token 和设备 ID。
- 配网模式从进入时开始计时；已有配置的设备 5 分钟没有任何 HTTP 配置/面板操作会自动重启进入正常模式。
- 配置页、登录页、保存请求和面板请求都会刷新配网活动计时；首次无配置时不自动退出配网模式。
- AP 模式和正常联网模式都提供 `/panel` 运行面板；正常联网后访问设备串口日志中打印的局域网 IP，例如 `http://设备IP/panel`。
- 配置页、运行面板、保存接口和退出接口均需要有效的管理会话 Cookie。
- 首次进入时先访问 `/setup-password` 设置至少 8 位管理密码；设备只保存带芯片 ID 盐值的 SHA-256 摘要，不保存明文密码。
- 登录成功后使用 `HttpOnly`、`SameSite=Strict`、30 分钟有效期的随机会话 Cookie；修改配置或密码后会话立即失效。
- 页面响应禁用缓存并发送 `X-Frame-Options: DENY`、`X-Content-Type-Options: nosniff` 等安全响应头。
- WS 地址支持 `ws://` 和 `wss://`，例如 `wss://10.0.0.10//ws`。
- WebSocket 断开、认证超时或发送失败时不会停止运行，会持续自动重连。
- 同时启用 WebSocket 库 Ping/Pong 心跳和服务端协议要求的 JSON `{"type":"ping"}` 应用层心跳。
- 固定长度环形日志缓冲避免长期运行时持续创建日志 `String` 导致堆碎片。
- WiFi 连接和 WebSocket 重连均为非阻塞状态机，主循环持续处理 GPIO0、HTTP、心跳和重连。
- 所有计时使用 `millis()` 差值比较，支持自然溢出，不依赖系统时间。
- 正常完成认证且数据发送成功时，内置 LED 每 3 秒短闪一次；配置模式下 LED 常亮。

## 构建、烧录与串口

使用 Arduino IDE 或其 CLI，开发板选择 `NodeMCU 1.0 (ESP-12E Module)`，端口选择设备管理器中显示的 CH340 串口。

```powershell
arduino-cli compile --fqbn esp8266:esp8266:nodemcuv2 src/main
arduino-cli upload -p COM6 --fqbn esp8266:esp8266:nodemcuv2 src/main
arduino-cli monitor -p COM6 -c baudrate=115200
```

上传的 `wifi` Envelope 中包含 `ssid`、`bssid`、`rssi`、`channel` 和 `encryption`；基站、蓝牙数据未上传。
