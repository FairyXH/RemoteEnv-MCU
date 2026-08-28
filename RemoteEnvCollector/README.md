# RemoteEnv Collector

ESP8266 本地环境采集器。完整的项目定位、目录结构、依赖、构建、烧录、配置和验证流程请参阅仓库根目录的 [`README.md`](../README.md)。

本目录对应 `RemoteEnvCollector/ESP8266` PlatformIO 工程，默认目标为 `nodemcuv2`。固件当前采集 Wi-Fi 环境信息，并通过配置的 WS/WSS 服务端进行认证和周期性上传。
