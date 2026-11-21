# 第三方依赖与来源

本仓库发布 TwinSail 本身的源码。Go 在构建时按 `go.mod` 获取第三方模块，用 `go.sum` 校验其内容。各依赖保留上游的版权声明与许可证。

| 直接依赖 | 用途 | 上游许可 |
| --- | --- | --- |
| `github.com/sagernet/quic-go` `v0.61.0-sing-box-mod.6` | QUIC 连接与流 | MIT，© 2016 the quic-go authors & Google, Inc. [上游许可证](https://github.com/SagerNet/quic-go/blob/v0.61.0-sing-box-mod.6/LICENSE) |
| `github.com/sagernet/sing-quic` `v0.7.1` | `congestion_meta2` 的 BBR 和 `hysteria/congestion` 的 Brutal 拥塞控制 | GPL-3.0-or-later，© 2022 nekohasekai。[上游许可证](https://github.com/SagerNet/sing-quic/blob/v0.7.1/LICENSE) |

`congestion_meta2` 的上游说明记录了它与 Clash.Meta 的渊源，BBR 实现也标注了 Google QUICHE 的参考版本。[sing-quic 来源说明](https://github.com/SagerNet/sing-quic/blob/v0.7.1/congestion_meta2/README.md) · [Clash.Meta 对应版本的许可证](https://github.com/MetaCubeX/mihomo/blob/dbaee284e4310aea71344f5154b174bd0333b657/LICENSE) · [Google QUICHE 对应版本的许可证](https://github.com/google/quiche/blob/e7872fc9e12bb1d46a118949c3d4da36de58aa44/LICENSE)

## 间接依赖

下列链接指向当前依赖清单所用版本的模块级许可。上游文件中保留了各组件的具体声明。

| 模块 | 许可文件 |
| --- | --- |
| `github.com/sagernet/sing` | [GPL-3.0-or-later](https://github.com/SagerNet/sing/blob/v0.9.0-beta.4/LICENSE) |
| `github.com/andybalholm/brotli` | [MIT](https://github.com/andybalholm/brotli/blob/v1.0.6/LICENSE) |
| `github.com/klauspost/compress` | [各组件的版权与许可证](https://github.com/klauspost/compress/blob/v1.17.9/LICENSE) |
| `github.com/metacubex/utls` | [BSD-3-Clause](https://github.com/MetaCubeX/utls/blob/v1.8.7/LICENSE) |
| `golang.org/x/crypto`、`golang.org/x/exp`、`golang.org/x/net`、`golang.org/x/sys` | BSD-3-Clause。 [crypto](https://github.com/golang/crypto/blob/v0.54.0/LICENSE) · [exp](https://github.com/golang/exp/blob/df9299821621/LICENSE) · [net](https://github.com/golang/net/blob/v0.56.0/LICENSE) · [sys](https://github.com/golang/sys/blob/v0.47.0/LICENSE) |
