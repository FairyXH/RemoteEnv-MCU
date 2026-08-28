# RemoteEnv Client

ESP8266 远程环境客户端。完整的项目定位、目录结构、依赖、构建、烧录、配置和验证流程请参阅仓库根目录的 [`README.md`](../README.md)。

本目录对应 `RemoteEnvClient/ESP8266` PlatformIO 工程，默认目标为 `nodemcuv2`。固件以 Consumer 角色连接 WS/WSS 服务端，获取设备列表并订阅选定的 Wi-Fi 环境快照，在受控测试环境中提供本地回放与状态展示能力。

`src/main/BeaconSimulator.*` 为设备能力适配层，`experiments/beacon_minimal/` 为独立的最小化实验工程。实验工程不属于默认构建入口，使用前请先确认硬件、无线环境和当地合规要求。

