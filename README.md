# TwinSail · 双帆

TwinSail 是用 Go 编写的 TCP 中继。客户端在本机提供 HTTP CONNECT 代理，服务端通过 IPv4 连接目标。两端使用 QUIC 和 TLS 1.3 双向证书认证。

默认情况下，客户端向同一服务端建立两条 QUIC 连接。上传走主通道，下行数据优先走主通道，累计达到 32 KiB 后开始分块轮转。一路已发包却迟迟收不到回复时，客户端按实测往返时延和波动调整等待时间，让新请求优先走另一条通道。若及时恢复，已有 TCP 会话可以沿原通道继续传输。持续中断的会话需要应用重新连接。

## 构建与测试

使用 Go 1.27.4，在仓库根目录执行：

```sh
go build -trimpath -o twinsail .
go test ./...
go vet ./...
```

常规测试会在回环接口上建立真实 TCP 和 QUIC 连接。下面的可选测试约需 64 秒，检查一端结束发送后，另一端仍能完整传送数据：

```sh
TWINSAIL_LONG_TESTS=1 go test -run TestLongLivedHalfClose -count=1 .
```

## 本机运行示例

准备同一 CA 签发的两张证书，按下表放置。服务端证书需要 DNS SAN `relay.internal` 和 `serverAuth` 用途，客户端证书需要 `clientAuth` 用途。程序使用固定名称 `relay.internal` 校验证书，实际连接地址由 `-endpoint` 指定。

| 目录 | 所需文件 |
| --- | --- |
| `pki/server/` | `ca.crt`、`server.crt`、`server.key` |
| `pki/client/` | `ca.crt`、`client.crt`、`client.key` |

在两个终端分别启动服务端和客户端。以下命令使用本机回环地址，客户端代理监听 TCP，服务端监听 UDP：

```sh
./twinsail -role server -endpoint 127.0.0.1:5443 -keys ./pki/server
```

```sh
./twinsail -role client -endpoint 127.0.0.1:5443 -listen 127.0.0.1:18080 -keys ./pki/client
```

用第三个终端请求一个 HTTPS 页面，收到目标站点的响应即可验证整条链路：

```sh
curl --fail --show-error --noproxy '' --proxy http://127.0.0.1:18080 https://example.com/
```

用 `./twinsail -h` 查看完整参数。`-lanes` 可设为 1 到 4，默认 2。客户端代理限回环地址，现有协议承载 TCP。两端保留 `r76-relay/1` 作为 ALPN 标识，以兼容既有实现。

## 源码导航

| 文件 | 职责 |
| --- | --- |
| `relay.go` | 启动入口、双向 TLS、目标拨号、连接管理和单通道转发 |
| `lanes.go` | 多通道配对、传输分块与按序交付 |
| `drain.go` | TCP 半关闭后继续传输，空闲超时后释放连接 |
| `copy.go` | 复用转发缓冲区，小流量按需扩容 |
| `*_test.go` | 并发、断线恢复、半关闭、分块交付和地址回退的回归测试 |

## 许可证

Copyright © 2026 TwinSail contributors. TwinSail 源码按 GNU 通用公共许可证第 3 版（`GPL-3.0-only`）发布。[许可证全文](LICENSE) · [第三方依赖与来源](THIRD_PARTY_NOTICES.md)
