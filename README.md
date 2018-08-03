# mbedTLS

## 1、介绍 

**mbedTLS**（前身 PolarSSL）是一个由 ARM 公司开源和维护的 SSL/TLS 算法库。其使用 C 编程语言以最小的编码占用空间实现了 SSL/TLS 功能及各种加密算法，易于理解、使用、集成和扩展，方便开发人员轻松地在嵌入式产品中使用 SSL/TLS 功能。

该 [mbedtls](https://github.com/RT-Thread-packages/mbedtls) 软件包是 **RT-Thread** 基于 [ARMmbed/mbedtls](https://github.com/ARMmbed/mbedtls/) 开源库的移植，有关 mbedTLS 的更多信息，请参阅 [https://tls.mbed.org](https://tls.mbed.org) 。

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

## 2、如何使用

示例程序 `samples/tls_app_test.c`。

### 2.1 启用软件包

- 配置软件包并使能示例

```shell
RT-Thread online packages --->
    security packages  --->
        [*] mbedtls: An portable and flexible SSL/TLS library  ---
        [*]   Store the AES tables in ROM
        (2)   Maximum window size used
        (3584) Maxium fragment length in bytes
        [*]   Enable a mbedtls client example
              version (latest)  --->
```

- 使用 `pkgs --update` 命令下载软件包

### 2.2 运行示例

该示例程序提供了一个简单的 TLS client，与支持安全连接的网站建立 TLS 连接并获取加密数据。

主要流程：

- client连接外网 TLS 测试网站 `www.howsmyssl.com`
- client 和 server 握手成功
- client 发送请求
- server 回应请求
- TLS 测试成功

在 MSH 中使用命令 **`tls_test`** 执行示例程序，如下所示：

```shell
msh />tls_test
mbedtls client struct init success...
Loading the CA root certificate success...
mbedtls client context init success...
Connected www.howsmyssl.com:443 success...
Certificate verified success...
Writing HTTP request success...
Getting HTTP response...
（get response data）....
```

## 3、常见问题

### 3.1 证书验证失败  

    [tls]verification info: ! The CRL is not correctly signed by the trusted CA

- 原因

    mbedtls包中支持多种主流CA机构根证书，部分CA机构未支持   

- 解决方法

    若测试其他TLS网站证书验证失败，手动获取测试网站根证书（Root Cerificate）添加到`mbedtls/tls_cerificate.c`文件中

### 3.2 证书时间错误

    verification info: ! The certificate validity has expired
    verification info: ! The certificate validity starts in the future

- 原因

    TLS握手是证书验证需要时间的验证，本地时间获取有误导致   

- 解决方式

    检查RTC设备是否支持，检查`RT_USING_RTC`宏是否打开，校准设备时间

### 3.3 证书 CN 错误

    verification info: ! The certificate Common Name (CN) does not match with the expected CN

- 原因

    测试其他TLS网站时，若输入域名不符合证书的Common Name（CN）出现CN验证失败问题   

- 解决方法

    检查输入域名和证书中CN是否匹配或输入IP地址

### 3.4 0x7200 错误

- 原因

    部分原因是因为 mbedTls 收到了大于缓冲区大小的数据包  

- 解决方法

    `menuconfig` 配置增加数据帧大小 ( `Maxium fragment length in bytes` )

```
RT-Thread online packages --->
    security packages  --->
        [*] mbedtls: An portable and flexible SSL/TLS library  ---
        [*]   Store the AES tables in ROM
        (2)   Maximum window size used
        (6144) Maxium fragment length in bytes
        [*]   Enable a mbedtls client example
              version (latest)  --->
```

## 4、参考资料

- mbedTLS官方网站：https://tls.mbed.org/
- ARMmbed GitHub：[mbedtls](https://github.com/ARMmbed/mbedtls/tree/72ea31b026e1fc61b01662474aa5125817b968bc)

## 5、 联系方式 & 感谢

- 维护： chenyong
- 主页： https://github.com/RT-Thread-packages/mbedtls
