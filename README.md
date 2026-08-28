
# RemoteEnv-MCU

面向微控制器和嵌入式设备的物联网环境采集与模拟客户端。项目将采集器（Collector）与客户端（Client）统一维护在同一仓库中：采集器从本地设备读取环境信息并上传到服务端，客户端从服务端获取选定的远程环境数据，在受控测试环境中进行本地回放或展示。

本仓库面向设备联调、协议验证、物联网数据采集、嵌入式系统测试和环境配置回放等场景。设备、服务端、网络和数据均应由使用者拥有或获得明确授权；示例配置只使用占位符，不包含生产凭据。

## 功能概览

- **MCU Collector**：连接 Wi-Fi 和 WS/WSS 服务端，周期性扫描本地 Wi-Fi 环境，按服务端协议上传结构化环境数据。
- **MCU Client**：以 Consumer 角色连接服务端，获取可用设备列表，订阅选定设备的 Wi-Fi 环境快照，并通过本地管理页面查看状态和控制运行配置。
- **设备管理**：首次启动或按键触发配置 AP；配置 Wi-Fi、服务端地址、Token 和设备标识；通过会话 Cookie 保护管理页面。
- **可靠运行**：非阻塞 Wi-Fi/WebSocket 重连、应用层心跳、串口日志和运行面板，便于现场联调和故障定位。
- **单射频适配**：ESP8266 Client 根据设备能力在管理网络连接与环境回放之间进行调度；实际可用范围受芯片、SDK、信道和法规限制。

## 仓库结构

```text
RemoteEnv-MCU/
├─ RemoteEnvCollector/
│  └─ ESP8266/
│     ├─ platformio.ini
│     └─ src/main/main.ino
├─ RemoteEnvClient/
│  └─ ESP8266/
│     ├─ platformio.ini
│     ├─ src/main/main.ino
│     ├─ src/main/BeaconSimulator.h/.cpp
│     └─ experiments/beacon_minimal/
└─ README.md
```

## 硬件与软件要求

- ESP8266 NodeMCU v2 / `NodeMCU 1.0 (ESP-12E Module)`，通过 USB-UART 连接电脑。
- Windows、Linux 或 macOS。
- VS Code + PlatformIO，或已安装 ESP8266 Arduino Core 的 Arduino IDE/CLI。
- 一个可访问的 RemoteEnvServer 实例，以及测试用 Token、设备标识和网络配置。
- 使用 WSS 时，服务端地址应使用 `wss://<host>:<port>/<path>`；敏感值只在设备配置页面填写，不要写入仓库。

PlatformIO 会依据各目录下的 `platformio.ini` 自动安装 ESP8266 平台及 `WebSockets`、`ArduinoJson` 依赖。当前配置目标为 `nodemcuv2`，串口监视速率为 `115200`。

## 构建

### 构建 Collector

在 PowerShell 中执行：

```powershell
cd D:\Files\Develop\IOT\RemoteEnv-MCU\RemoteEnvCollector\ESP8266
pio run -e nodemcuv2
```

### 构建 Client

```powershell
cd D:\Files\Develop\IOT\RemoteEnv-MCU\RemoteEnvClient\ESP8266
pio run -e nodemcuv2
```

构建产物位于对应项目的 `.pio/build/nodemcuv2/`，包括固件镜像和 ELF 文件。`.pio/` 属于本地生成目录，不应提交到仓库。

### Arduino IDE/CLI

也可以将相应项目的 `src/main/main.ino` 作为 Arduino 工程入口，开发板选择 `NodeMCU 1.0 (ESP-12E Module)`，并安装 `WebSockets`、`ArduinoJson` 及源码所需的 ESP8266 库。使用 Arduino CLI 时，先进入包含 `src/main` 的项目目录：

```powershell
arduino-cli compile --fqbn esp8266:esp8266:nodemcuv2 src/main
```

PlatformIO 是本仓库推荐方式，因为它能够直接使用已提交的板卡和依赖配置。

## 烧录

1. 用 USB 数据线连接 NodeMCU，确认驱动已识别串口。
2. 查询串口：

   ```powershell
   pio device list
   ```

3. 在对应项目目录执行上传，将 `COMx` 替换为实际端口：

   ```powershell
   pio run -e nodemcuv2 -t upload --upload-port COMx
   ```

4. 打开串口监视器：

   ```powershell
   pio device monitor --port COMx --baud 115200
   ```

如果上传失败，先关闭占用该串口的串口监视器、Arduino IDE 或其他工具，再重新枚举端口。不要仅根据 IDE 的界面状态判断烧录成功；应确认上传命令成功结束，并在串口日志中看到固件启动信息。

Arduino CLI 的对应命令如下：

```powershell
arduino-cli upload -p COMx --fqbn esp8266:esp8266:nodemcuv2 src/main
arduino-cli monitor -p COMx -c baudrate=115200
```

## 首次配置与运行

### Collector

1. 烧录后打开串口监视器，记录设备创建的配置 AP 和访问地址。
2. 连接配置 AP，访问设备提示的本地管理地址。
3. 首次进入时设置管理密码，然后填写 Wi-Fi、WS/WSS 地址、服务端 Token 和唯一设备标识。
4. 保存后设备连接服务端；认证成功后按固定周期上传 `wifi` 类型环境数据。
5. 在设备串口日志或运行面板中确认 Wi-Fi、WebSocket、认证和上传状态。

### Client

1. 使用同样的方式配置 Wi-Fi、WS/WSS 地址、Consumer Token 和管理密码。
2. 登录 `/devices` 页面查看服务端返回的设备列表。
3. 选择一个已授权的设备并订阅 `wifi` 数据。
4. 在 `/panel` 页面观察 WebSocket、数据更新时间、网络数量和本地回放状态。

客户端的设备选择是运行时状态；配置页面负责持久化网络和服务端参数。单射频设备无法同时在所有 Wi-Fi 信道上维持连接和进行回放，信道调度由固件根据当前连接状态处理。

## 服务端数据约定

设备通过 WebSocket 发送 JSON 消息。典型流程为：建立连接 → `auth` 认证 → Collector 发送 `environment_data`，或 Client 发送 `subscribe` / `refresh` → 服务端返回设备列表和环境数据。环境数据使用 `data_type` 区分类型；本仓库当前实现重点支持 `wifi`，包含 SSID、BSSID、信号强度、信道和加密类型等字段。

服务端地址、Token、设备 ID 和 Wi-Fi 密码均属于部署配置，不应提交到 Git，也不应复制进公开日志或问题报告。建议为不同测试环境使用独立的临时标识和最小授权 Token。

## 验证清单

- `pio run -e nodemcuv2` 构建成功且没有编译错误。
- `pio run -e nodemcuv2 -t upload --upload-port COMx` 成功完成。
- 串口日志显示固件正常启动，且波特率为 `115200`。
- Collector 能完成 Wi-Fi 连接、WebSocket 认证和周期性数据发送。
- Client 能获取设备列表、完成订阅并显示新鲜的 Wi-Fi 快照。
- 服务端 Token、设备授权和数据范围符合当前测试环境的预期。

构建成功只证明代码和工具链通过编译，不等同于真实硬件、无线环境或服务端联调已经验证。

## 注意事项

- 不要将真实 Wi-Fi 密码、Token、服务端地址或设备标识写入源码、提交记录和公开截图。
- 使用 WSS 时应根据部署要求配置证书验证策略，并在受控网络中进行联调。
- `experiments/beacon_minimal` 是独立的最小化验证工程，不是主 Client 的生产入口；使用前应确认目标硬件和测试环境满足要求。
- 无线信道、发射功率、频段和数据回放行为必须符合设备所在地的法律法规、无线电管理要求以及实验环境规定。

## 许可证

仓库当前未提供统一的许可证文件。对外发布前请补充与依赖许可证兼容的项目许可证，并确认服务端及相关库的授权范围。
