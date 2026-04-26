# singbox_dash

sing-box 代理服务管理面板——本地 Web UI，用于构建和管理 sing-box 服务端/客户端配置。

## 功能特性

- **多协议支持**：VLESS（含 Vision Flow）、Trojan、Hysteria2、Shadowsocks
- **TLS 灵活配置**：标准 TLS（证书文件 / 自签名 / ACME）、Reality 协议
- **证书管理**：手动文件、自签名、ACME（HTTP-01 / TLS-ALPN-01 / DNS-01）、Reality 密钥对
- **配置导出**：一键导出 sing-box 服务端/客户端 JSON 配置
- **订阅链接**：生成 vless://、trojan://、hysteria2://、ss:// 分享链接
- **运行时管理**：面板内直接启动/停止/重启 sing-box 进程，查看状态和日志

## 项目结构

```text
app.go              入口，加载状态并启动 HTTP 服务
models.go           数据模型（AppState/Certificate/Service/User）+ 默认值 + 规范化
store.go            状态持久化（load/snapshot/replace/mutex-safe mutate）
server.go           HTTP 处理器 + 工具函数（randomHex/randomUUID/nextPort）
config_export.go    sing-box 服务端/客户端配置生成 + 订阅链接
certificate.go      证书管理（ACME/自签名/Reality 密钥对）
runtime.go          sing-box 进程管理（start/stop/status/apply）
web.go              路由注册 + 静态资源嵌入
json_helpers.go     JSON 编解码封装
sync_alias.go       sync.RWMutex 类型别名
web/                前端资源
```

## 快速开始

```bash
# 构建
go build -o singbox_dash .

# 运行
./singbox_dash
```

打开浏览器访问：http://127.0.0.1:8088

状态数据保存在 `data/state.json`。

## API 路由

| 路由 | 方法 | 说明 |
|------|------|------|
| `/api/state` | GET/PUT | 读取/替换全局状态 |
| `/api/service` | POST | 创建新服务 |
| `/api/service/{id}` | DELETE | 删除服务 |
| `/api/service/{id}/reality-keypair` | POST | 生成 Reality 密钥对 |
| `/api/certificate` | POST | 创建新证书 |
| `/api/certificate/{id}` | DELETE | 删除证书 |
| `/api/certificate/{id}/issue` | POST | 签发证书 |
| `/api/certificate/{id}/status` | POST | 刷新证书状态 |
| `/api/certificate/{id}/reality-keypair` | POST | 生成 Reality 密钥对 |
| `/api/validate/server` | POST | 验证服务端配置 |
| `/api/runtime/apply` | POST | 应用配置到 sing-box |
| `/api/runtime/status` | GET | 查询运行时状态 |
| `/api/runtime/stop` | POST | 停止 sing-box 进程 |
| `/export/server.json` | GET | 导出服务端配置 |
| `/export/client.json` | GET | 导出客户端配置 |
| `/sub/{token}` | GET | 订阅链接端点 |

## sing-box 运行时管理

面板可直接管理本地 sing-box 进程（无需 systemd）：

1. **检测配置** — 运行 `sing-box check` 验证配置合法性
2. **应用到 sing-box** — 写入配置 → 校验 → 停止旧进程 → 启动新进程
3. **运行时面板** — 查看进程状态、PID、日志

默认运行时文件：

```text
data/runtime/server.json    生成的服务端配置
data/runtime/sing-box.pid   进程 PID
data/runtime/sing-box.log   运行日志
```

## 证书管理

| 模式 | 说明 |
|------|------|
| `file` | 手动指定证书文件路径 |
| `self_signed` | 面板生成 RSA 2048 自签名证书（有效期 1 年） |
| `acme_http` | ACME HTTP-01 验证（`acme.sh --standalone` 或 webroot） |
| `acme_tls_alpn` | ACME TLS-ALPN-01 验证（`acme.sh --alpn`） |
| `acme_dns` | ACME DNS-01 验证（`acme.sh --dns <provider>`） |
| `reality` | Reality 协议密钥对管理 |

ACME 模式需先安装 [acme.sh](https://github.com/acmesh-official/acme.sh)。DNS-01 凭据以多行环境变量格式填写：

```text
CF_Token=...
CF_Account_ID=...
```

托管证书默认存储在 `data/certs/<certificate-id>/`。

## 注意事项

本项目为原型实现，**请勿直接暴露到公网**。生产环境使用前需添加：
- 面板认证与 HTTPS
- 更严格的输入验证
- 防火墙与进程权限控制

## License

MIT
