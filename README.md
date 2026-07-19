# WG

**简体中文** · [English](./README.en.md) · [日本語](./README.ja.md)

> 填写服务器 IP、管理分流结果，并保持系统 DNS 不被修改——这是 WG 希望提供的私有隧道体验。

[WG](https://github.com/Aiweline/WG) 是一个使用 Go 开发的轻量级智能分流私有隧道项目。客户端提供图形界面，服务端通过脚本和命令行管理；域名、IP 和 CIDR 的分流结果可以随时调整，删除人工覆盖项后会重新交给 <code>AUTO</code> 智能分类。

> [!NOTE]
> WG 提供可用的 TCP 代理和加密 UDP 中继；它不创建 TUN、系统路由、防火墙或 NAT 规则，因此不会污染系统 DNS。它不是 WireGuard 兼容实现，也不应被配置为系统级全局 VPN。

## TCP / UDP 数据面

`wg-proxy` 是实际数据面：TCP 模式为 TLS 保护、令牌认证的 HTTP/HTTPS CONNECT 代理；UDP 模式为令牌认证、AES-256-GCM 保护的请求/响应 UDP 中继。TCP 和 UDP 可同时使用同一个端口号 `9518`（分别占用 TCP/UDP 协议），客户端仅监听回环地址。`-direct-host` 支持 TCP 的按域名后缀直连，整个过程不修改系统 DNS、路由或防火墙。

> [!IMPORTANT]
> UDP 中继要求客户端明确指定 `-target host:port`，适用于 DNS、游戏或其他固定 UDP 服务。它不是透明 UDP/TUN；服务端令牌和证书必须通过安全渠道发放并定期轮换。

服务端示例：

~~~sh
wg-proxy server \
  -listen :9518 \
  -cert ./server-cert.pem \
  -key ./server-key.pem \
  -token "$WG_PROXY_TOKEN"
~~~

长期运行时，使用只允许服务账户读取的令牌文件，避免令牌出现在进程参数中：

~~~sh
chmod 600 /etc/wg-proxy/token
wg-proxy server \
  -listen <private-interface-ip>:9518 \
  -cert /etc/wg-proxy/server-cert.pem \
  -key /etc/wg-proxy/server-key.pem \
  -token-file /etc/wg-proxy/token
~~~

如果本机已有服务占用 `127.0.0.1:9518`，WG 可以仅绑定服务器私网网卡地址；公网 EIP/NAT 仍可将 TCP 9518 转到该监听，不会影响该回环服务。

客户端示例：

~~~sh
wg-proxy client \
  -listen 127.0.0.1:47101 \
  -server SERVER_IP:9518 \
  -ca ./server-cert.pem \
  -token "$WG_PROXY_TOKEN" \
  -direct-host example.com

curl --proxy http://127.0.0.1:47101 https://icanhazip.com
~~~

### Web UI 中的一键真实测试

启动 TCP 与 UDP 客户端后，启动客户端 UI 并打开 `http://127.0.0.1:4173`：

~~~sh
./bin/wg-client-ui --listen 127.0.0.1:4173 --assets ui/client/dist
~~~

进入“健康与更新”，选择“开始真实测试”。UI 后台只会访问本机的 `127.0.0.1:47101` TCP 代理和 `127.0.0.1:47102` UDP 中继，分别验证真实公网出口、UDP DNS 往返，以及 UI 启动后系统 DNS 指纹是否保持不变；页面不会读取或显示令牌。

UDP 服务端与客户端（与 TCP 使用相同令牌，默认同为 `9518`）：

~~~sh
# server: UDP/9518
wg-proxy udp-server -listen :9518 -token-file /etc/wg-proxy/token

# client: expose a loopback UDP relay for one selected destination
wg-proxy udp-client \
  -listen 127.0.0.1:47102 \
  -server SERVER_IP:9518 \
  -target 1.1.1.1:53 \
  -token "$WG_PROXY_TOKEN"
~~~

## 一键安装脚本

以下是实际 TCP/UDP 数据面脚本；它们不会修改系统 DNS、路由、NAT 或防火墙。请先通过安全渠道将服务端证书和令牌提供给客户端。

### macOS / Linux 客户端

~~~sh
make build
./scripts/wg-client proxy start tcp \
  --server SERVER_IP:9518 --ca ./server-cert.pem --token-file ./token

# 切换为 UDP：暴露一个只连接到指定目标的本地 UDP 中继
./scripts/wg-client proxy start udp \
  --server SERVER_IP:9518 --target 1.1.1.1:53 --token-file ./token
~~~

### Linux 服务端

~~~sh
make build
sudo WG_PROXY_BIN="$PWD/bin/wg-proxy" ./scripts/wg-server proxy install \
  --server-ip YOUR_PUBLIC_IP --listen :9518
~~~

### Windows（PowerShell）

~~~powershell
git clone https://github.com/Aiweline/WG.git
Set-Location WG
wsl bash ./scripts/wg-client install 203.0.113.10 ./wg-pairing.wgp --dry-run
~~~

安装脚本会创建 `wg-proxy-tcp.service` 和 `wg-proxy-udp.service` 并设置开机自启。若 `127.0.0.1:9518` 已有本地服务，请将 `--listen` 指向服务器私网网卡地址，例如 `172.23.33.165:9518`。

## 核心特点

- **智能分流**：<code>AUTO</code> 自动判断目标，也可以显式设为 <code>TUNNEL</code>、<code>DIRECT</code> 或 <code>BLOCK</code>。
- **结果可管理**：支持域名、IP 和 CIDR 覆盖项；删除后恢复自动分类。
- **私有 DNS 副本**：只读复制系统解析器配置，使用独立 generation 和私有 TTL 缓存；没有修改系统 DNS 的接口。
- **客户端有 UI，服务端无 UI**：客户端展示连接、分流、DNS、健康和配对；服务端由 <code>wg-server</code> 脚本管理。
- **安全开发优先**：管理端口只允许回环地址，生产网络模式会被明确拒绝。

<code>WG/1</code> 与 <code>WG-HS/1</code> 是项目定义的实验性格式和状态机，**不代表 WireGuard 兼容性**。底层密码能力使用 Go 生态中的 X25519、ChaCha20-Poly1305、BLAKE2s 和 HKDF 实现；项目没有自创底层密码原语，也尚未通过独立安全审计。

## 当前已实现

| 模块 | 安全开发版能力 |
| --- | --- |
| <code>internal/codec</code> | 有界的 <code>WG/1</code> 报文、TLV 和内层帧解析与序列化，含单元测试与 fuzz 入口 |
| <code>internal/crypto</code> | 标准密码原语、规范指纹和握手/传输高层接口 |
| <code>internal/handshake</code> | 已登记客户端的内存内 <code>WG-HS/1</code> 握手开发路径 |
| <code>internal/session</code> | 客户端/服务端状态机、包号与重放防护 |
| <code>internal/routing</code> | 域名、IP、CIDR 与四类分流决策 |
| <code>internal/privatedns</code> | 系统解析器只读快照、generation 隔离和私有 TTL 缓存 |
| <code>internal/controlapi</code> | 有大小、超时和并发上限的本地管理 API |
| <code>cmd</code> / <code>ui</code> / <code>scripts</code> | 安全 control core、五页客户端 UI 和真实 TCP/UDP 代理脚本 |

安全 control core 验证架构与管理流程；<code>wg-proxy</code> 承载真实代理流量。

## 架构

~~~text
客户端 UI（React，由 Go 主机托管）
        │  http://127.0.0.1:4173
        ▼
wg-client-ui
        │  /api/v1
        ▼
wg-core client（回环管理 API）
        ├── WG/1 + WG-HS/1
        ├── crypto + session
        ├── AUTO 智能分流
        └── 私有 DNS 快照与缓存

wg-core server（无 UI，脚本管理）
        └── 安全模式仅记录数据监听配置

UDP / TUN / 系统路由 / 防火墙 / NAT
        └── 尚未接入
~~~

## 客户端界面

![WG 客户端连接页原型](./docs/ui-prototypes/wg-client-01-connection.png)

客户端包含连接、智能分流、私有 DNS、健康与更新、首次配对五个页面。更多原型位于 [docs/ui-prototypes](./docs/ui-prototypes)。

## 环境要求

- Go 1.26+
- Node.js 20+
- <code>make</code>

## 快速开始

~~~sh
git clone https://github.com/Aiweline/WG.git
cd WG
npm --prefix ui/client install
make build
~~~

启动安全开发客户端 core：

~~~sh
WG_DEV_SAFE=1 ./bin/wg-core client \
  --dev-safe \
  --no-host-network \
  --management-address 127.0.0.1:47003 \
  --endpoint 203.0.113.10:9518
~~~

<code>203.0.113.10</code> 是 TEST-NET 文档示例地址。当前版本只记录端点，不会建立真实隧道。

在另一个终端启动客户端 UI：

~~~sh
./bin/wg-client-ui \
  --listen 127.0.0.1:4173 \
  --assets ui/client/dist \
  --core http://127.0.0.1:47003
~~~

打开 [http://127.0.0.1:4173/](http://127.0.0.1:4173/)。

可选的安全开发服务端 core：

~~~sh
WG_DEV_SAFE=1 ./bin/wg-core server \
  --dev-safe \
  --no-host-network \
  --management-address 127.0.0.1:47002 \
  --listen 0.0.0.0:9518
~~~

安全模式中的 <code>--listen</code> 只是配置记录，不会打开 UDP 端口。

## WG 脚本

以下命令是彼此独立的 dry-run 示例：

~~~sh
./scripts/wg-server install 203.0.113.10 --dry-run

./scripts/wg-server pair \
  --output ./wg-pairing.wgp \
  --expires 10m \
  --dry-run

./scripts/wg-client install \
  203.0.113.10 \
  ./wg-pairing.wgp \
  --dry-run
~~~

> [!IMPORTANT]
> dry-run 不保证生成配对文件。真实安装尚未完成，<code>install --execute</code> 会明确失败；这些命令不能作为生产部署步骤。

## 项目结构

~~~text
cmd/                    wg-core 与 wg-client-ui
internal/               协议、会话、分流、DNS 和控制 API
scripts/                wg-client 与 wg-server
ui/client/              客户端 UI
docs/ui-prototypes/     多页面原型
tests/                  跨包与边界测试
~~~

## 验证

~~~sh
go test ./cmd/... ./internal/... ./tests/...
go test -race ./cmd/... ./internal/... ./tests/...
go vet ./cmd/... ./internal/... ./tests/...
npm --prefix ui/client run build
sh -n scripts/wg-client
sh -n scripts/wg-server
~~~

## 进入生产前必须完成

- UDP 传输、真实 TUN 数据面、IPv4/IPv6、MTU 与流量加密集成。
- 原子路由事务、最小权限辅助程序、服务隔离、防火墙/NAT 与失败回滚。
- 完整私有 DNS socket、逐链路解析器快照和 TTL 刷新。
- 持久化客户端登记、正式密钥生命周期、一次性登记和 RETRY 状态机。
- 签名发布、供应链校验、打包、跨平台测试和独立安全审计。

## 参与贡献

欢迎提交 Issue 和 Pull Request。请保持安全开发模式为默认值，为行为变化补充测试，并在提交前运行全部验证命令。

涉及协议、密码、重放防护、分流、DNS 或系统网络设置的变更，请说明兼容性、安全影响与验证依据。
