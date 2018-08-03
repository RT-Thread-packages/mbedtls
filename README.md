# mbedTLS

## 1、介绍 

**mbedTLS**（前身 PolarSSL）是一个由 ARM 公司开源和维护的 SSL/TLS 算法库。其使用 C 编程语言以最小的编码占用空间实现了 SSL/TLS 功能及各种加密算法，易于理解、使用、集成和扩展，方便开发人员轻松地在嵌入式产品中使用 SSL/TLS 功能。

该 [mbedtls](https://github.com/RT-Thread-packages/mbedtls) 软件包是 **RT-Thread** 基于 [ARMmbed/mbedtls](https://github.com/ARMmbed/mbedtls/) 开源库的移植，有关 mbedTLS 的更多信息，请参阅 [软件包详细介绍](docs/introduction.md) 。

### 1.1 目录结构

| 名称            | 说明 |
| ----            | ---- |
| docs            | 文档目录 |
| mbedtls         | ARM mbedtls 源码 |
| ports           | 移植文件目录 |
| samples         | 示例文件目录 |
| LICENSE         | 许可证文件 |
| README.md       | 软件包使用说明 |
| SConscript      | RT-Thread 默认的构建脚本 |

### 1.2 许可证

Apache License Version 2.0 协议许可。

## 2、获取软件包

在使用的 BSP 目录下，使用 ENV 工具打开 menuconfig 来获取软件包。

- 配置软件包并使能示例

```shell
RT-Thread online packages --->
    security packages  --->
        [*] mbedtls: An portable and flexible SSL/TLS library  ---  # 打开 mbedtls 软件包
        [*]   Store the AES tables in ROM      # 将 AES 表存储在 ROM 中，优化内存占用
        (2)   Maximum window size used         # 用于点乘的最大“窗口”大小（2-7，该值越小内存占用也越小）
        (3584) Maxium fragment length in bytes # 配置数据帧大小（0x7200 错误可尝试增加该大小）
        [*]   Enable a mbedtls client example  # 开启 mbedtls 测试例程
        [ ]   Enable Debug log output          # 开启调试 log 输出
              version (latest)  --->           # 选择软件包版本，默认为最新版本
```

- 使用 `pkgs --update` 命令下载软件包

## 3、使用 mbedtls

- 如何从零开始使用，请参考 [用户手册](docs/user-guide.md)。
- 完整的 API 文档，请参考 [API 手册](docs/api.md)。
- 详细的示例介绍，请参考 [示例文档](docs/samples.md) 。
- mbedtls 协议工作原理，请参考 [工作原理](docs/principle.md) 。
- 更多**详细介绍文档**位于 [`/docs`](/docs) 文件夹下，**使用软件包进行开发前请务必查看**。

## 4、参考资料

- mbedTLS官方网站：https://tls.mbed.org/
- ARMmbed GitHub：[mbedtls](https://github.com/ARMmbed/mbedtls/tree/72ea31b026e1fc61b01662474aa5125817b968bc)

## 5、 联系方式 & 感谢

- 维护： RT-Thread 开发团队
- 主页： https://github.com/RT-Thread-packages/mbedtls
