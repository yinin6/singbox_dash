// models.go - 数据模型与状态规范化
//
// 职责：
//   - 定义应用核心数据结构：AppState、PanelSettings、Certificate、Service、User 等
//   - defaultState() 生成初始默认状态（含 VLESS/Trojan/Hysteria2 示例服务）
//   - normalizeState() 填充缺失字段，保证状态完整性
//   - cloneState() 深拷贝状态，用于并发安全的事务操作
package main

import (
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"time"
)

// AppState 是应用的顶层状态结构，对应 data/state.json 文件
type AppState struct {
	Panel        PanelSettings `json:"panel"`        // 面板全局配置
	Certificates []Certificate `json:"certificates"` // 证书配置列表
	Services     []Service     `json:"services"`     // 代理服务列表
	UpdatedAt    time.Time     `json:"updated_at"`   // 最后更新时间
}

// PanelSettings 面板全局配置，包含服务器域名、DNS 策略、订阅令牌和 sing-box 运行时路径
type PanelSettings struct {
	Host              string `json:"host"`                // 服务器域名/IP
	DNSStrategy       string `json:"dns_strategy"`        // DNS 解析策略 (prefer_ipv4 / prefer_ipv6 / ipv4_only / ipv6_only)
	SubToken          string `json:"sub_token"`           // 订阅端口的鉴权令牌
	SingBoxPath       string `json:"sing_box_path"`       // sing-box 可执行文件路径
	RuntimeConfigPath string `json:"runtime_config_path"` // 运行时配置文件路径
	RuntimePIDPath    string `json:"runtime_pid_path"`    // 运行时 PID 文件路径
	RuntimeLogPath    string `json:"runtime_log_path"`    // 运行时日志文件路径
	AutoRestart       bool   `json:"auto_restart"`        // 应用配置时是否自动重启 sing-box
}

// Certificate 证书配置，支持多种模式：手动文件、自签名、ACME、Reality
type Certificate struct {
	ID                 string    `json:"id"`                   // 证书唯一标识
	Name               string    `json:"name"`                 // 证书显示名称
	Mode               string    `json:"mode"`                 // 证书模式: file / self_signed / acme_http / acme_tls_alpn / acme_dns / reality
	ServerName         string    `json:"server_name"`          // 证书域名 (SNI)
	CertPath           string    `json:"cert_path"`            // 证书文件路径 (fullchain)
	KeyPath            string    `json:"key_path"`             // 私钥文件路径
	Email              string    `json:"email"`                // ACME 注册邮箱
	CA                 string    `json:"ca"`                   // ACME 证书颁发机构 (letsencrypt / zerossl / buypass)
	Challenge          string    `json:"challenge"`            // ACME 验证方式: http / dns / tls_alpn
	Webroot            string    `json:"webroot"`              // HTTP-01 验证的 webroot 路径（留空则用 standalone）
	DNSProvider        string    `json:"dns_provider"`         // DNS-01 验证的 DNS 服务商 (如 cloudflare)
	DNSCredentials     string    `json:"dns_credentials"`      // DNS-01 所需的环境变量（每行一个 KEY=VALUE）
	AutoRenew          bool      `json:"auto_renew"`           // 是否自动续签（预留字段）
	LastStatus         string    `json:"last_status"`          // 最近操作状态: not_issued / issued / valid / error / missing / renew_due / ready / manual
	LastMessage        string    `json:"last_message"`         // 最近操作的描述信息
	LastIssuedAt       time.Time `json:"last_issued_at"`       // 最近签发时间
	ExpiresAt          time.Time `json:"expires_at"`           // 证书过期时间
	RealityPort        int       `json:"reality_port"`         // Reality 握手目标端口
	RealityPrivateKey  string    `json:"reality_private_key"`  // Reality 私钥
	RealityPublicKey   string    `json:"reality_public_key"`   // Reality 公钥
	RealityShortID     string    `json:"reality_short_id"`     // Reality Short ID
	RealityMaxTimeDiff string    `json:"reality_max_time_diff"` // Reality 最大时间差（如 "1m"）
	UTLSFingerprint    string    `json:"utls_fingerprint"`     // uTLS 指纹 (如 chrome / firefox / safari)
}

// Service 代理入站服务配置，对应 sing-box 的一个 inbound
type Service struct {
	ID                     string `json:"id"`                        // 服务唯一标识
	Name                   string `json:"name"`                      // 服务显示名称
	Protocol               string `json:"protocol"`                  // 协议类型: vless / trojan / hysteria2 / shadowsocks
	Enabled                bool   `json:"enabled"`                   // 是否启用
	Listen                 string `json:"listen"`                    // 监听地址 (如 "::" 表示双栈)
	Port                   int    `json:"port"`                      // 监听端口
	TLS                    bool   `json:"tls"`                       // 是否启用 TLS
	TLSMode                string `json:"tls_mode"`                  // TLS 模式: standard / reality
	CertID                 string `json:"cert_id"`                   // 关联的证书 ID
	Transport              string `json:"transport"`                 // 传输层: tcp / ws / grpc / http / udp
	Path                   string `json:"path"`                      // WebSocket/HTTP 路径 或 gRPC service name
	Method                 string `json:"method"`                    // Shadowsocks 加密方法
	RealityHandshakeServer string `json:"reality_handshake_server"`  // Reality 握手服务器（服务级覆盖）
	RealityHandshakePort   int    `json:"reality_handshake_port"`    // Reality 握手端口（服务级覆盖）
	RealityPrivateKey      string `json:"reality_private_key"`       // Reality 私钥（服务级覆盖）
	RealityPublicKey       string `json:"reality_public_key"`        // Reality 公钥（服务级覆盖）
	RealityShortID         string `json:"reality_short_id"`          // Reality Short ID（服务级覆盖）
	RealityMaxTimeDiff     string `json:"reality_max_time_diff"`     // Reality 最大时间差（服务级覆盖）
	UTLSFingerprint        string `json:"utls_fingerprint"`          // uTLS 指纹（服务级覆盖）
	Users                  []User `json:"users"`                     // 用户列表
}

// User 代理用户，每个用户拥有独立的 UUID 或密码凭据
type User struct {
	ID       string `json:"id"`       // 用户唯一标识
	Name     string `json:"name"`     // 用户显示名称
	UUID     string `json:"uuid"`     // VLESS 用户 UUID
	Password string `json:"password"` // Trojan/Hysteria2/Shadowsocks 用户密码
	Flow     string `json:"flow"`     // VLESS Flow（如 xtls-rprx-vision）
}

// Store 状态存储，使用读写锁保护并发访问
type Store struct {
	mu    RWMutex   // 读写锁，保证并发安全
	state AppState  // 当前应用状态
}

// subscriptionLine 订阅链接中的一行，用于生成客户端分享链接
type subscriptionLine struct {
	Name string `json:"name"` // 链接名称
	URL  string `json:"url"`  // 完整分享链接 (vless:// / trojan:// / hysteria2:// / ss://)
}

// RealityProfile Reality 协议的配置摘要，从 Certificate 或 Service 中提取
type RealityProfile struct {
	HandshakeServer string // 握手目标服务器域名
	HandshakePort   int    // 握手目标端口
	PrivateKey      string // 服务端私钥
	PublicKey       string // 客户端公钥
	ShortID         string // Short ID
	MaxTimeDiff     string // 最大时间差
	Fingerprint     string // uTLS 指纹
}

// defaultState 生成初始默认状态
// 包含一个 VLESS+Vision+TLS 服务、一个 Trojan 服务和一个 Hysteria2 服务
// 首次运行或 state.json 不存在时调用
func defaultState() AppState {
	token := randomHex(16)
	certID := "cert-default"
	return AppState{
		Panel: PanelSettings{
			Host:              "example.com",
			DNSStrategy:       "prefer_ipv4",
			SubToken:          token,
			SingBoxPath:       "sing-box",
			RuntimeConfigPath: filepath.ToSlash(filepath.Join(stateDir, "runtime", "server.json")),
			RuntimePIDPath:    filepath.ToSlash(filepath.Join(stateDir, "runtime", "sing-box.pid")),
			RuntimeLogPath:    filepath.ToSlash(filepath.Join(stateDir, "runtime", "sing-box.log")),
			AutoRestart:       true,
		},
		Certificates: []Certificate{
			{
				ID:          certID,
				Name:        "Default TLS",
				Mode:        "file",
				ServerName:  "example.com",
				CertPath:    "/etc/sing-box/cert/fullchain.pem",
				KeyPath:     "/etc/sing-box/cert/privkey.pem",
				Email:       "admin@example.com",
				CA:          "letsencrypt",
				Challenge:   "http",
				AutoRenew:   true,
				LastStatus:  "manual",
				LastMessage: "manual file certificate",
			},
		},
		Services: []Service{
			{
				ID:        "svc-vless-ws",
				Name:      "VLESS TCP Vision TLS",
				Protocol:  "vless",
				Enabled:   true,
				Listen:    "::",
				Port:      443,
				TLS:       true,
				TLSMode:   "standard",
				CertID:    certID,
				Transport: "tcp",
				Users: []User{
					{ID: "user-main", Name: "main", UUID: randomUUID(), Password: randomHex(12), Flow: "xtls-rprx-vision"},
				},
			},
			{
				ID:        "svc-trojan",
				Name:      "Trojan TCP TLS",
				Protocol:  "trojan",
				Enabled:   false,
				Listen:    "::",
				Port:      8443,
				TLS:       true,
				TLSMode:   "standard",
				CertID:    certID,
				Transport: "tcp",
				Users: []User{
					{ID: "user-trojan", Name: "trojan", UUID: randomUUID(), Password: randomHex(14)},
				},
			},
			{
				ID:        "svc-hy2",
				Name:      "Hysteria2 UDP",
				Protocol:  "hysteria2",
				Enabled:   false,
				Listen:    "::",
				Port:      8444,
				TLS:       true,
				TLSMode:   "standard",
				CertID:    certID,
				Transport: "udp",
				Users: []User{
					{ID: "user-hy2", Name: "hy2", UUID: randomUUID(), Password: randomHex(14)},
				},
			},
		},
		UpdatedAt: time.Now(),
	}
}

// normalizeState 填充状态中缺失的字段，确保数据完整性
// 在每次加载和更新状态后调用，包括：
//   - Panel 配置缺失字段填充默认值
//   - 证书字段规范化（ACME 模式映射、路径修正、Reality 状态检查）
//   - 服务字段规范化（协议默认值、用户凭据补全）
func normalizeState(s *AppState) {
	// --- Panel 配置默认值 ---
	if s.Panel.Host == "" {
		s.Panel.Host = "example.com"
	}
	if s.Panel.DNSStrategy == "" {
		s.Panel.DNSStrategy = "prefer_ipv4"
	}
	if s.Panel.SubToken == "" {
		s.Panel.SubToken = randomHex(16)
	}
	if s.Panel.SingBoxPath == "" {
		s.Panel.SingBoxPath = "sing-box"
	}
	if s.Panel.RuntimeConfigPath == "" {
		s.Panel.RuntimeConfigPath = filepath.ToSlash(filepath.Join(stateDir, "runtime", "server.json"))
	}
	if s.Panel.RuntimePIDPath == "" {
		s.Panel.RuntimePIDPath = filepath.ToSlash(filepath.Join(stateDir, "runtime", "sing-box.pid"))
	}
	if s.Panel.RuntimeLogPath == "" {
		s.Panel.RuntimeLogPath = filepath.ToSlash(filepath.Join(stateDir, "runtime", "sing-box.log"))
	}

	// --- 证书字段规范化 ---
	for i := range s.Certificates {
		cert := &s.Certificates[i]
		if cert.ID == "" {
			cert.ID = "cert-" + randomHex(6)
		}
		if cert.Mode == "" {
			cert.Mode = "file"
		}
		// 兼容旧版 "acme" 模式，映射为 "acme_http"
		if cert.Mode == "acme" {
			cert.Mode = "acme_http"
		}
		if cert.CA == "" {
			cert.CA = "letsencrypt"
		}
		// 根据模式推断验证方式
		if cert.Challenge == "" {
			switch cert.Mode {
			case "acme_dns":
				cert.Challenge = "dns"
			case "acme_tls_alpn":
				cert.Challenge = "tls_alpn"
			default:
				cert.Challenge = "http"
			}
		}
		if cert.ServerName == "" {
			cert.ServerName = s.Panel.Host
		}
		// Reality 模式的 ServerName 不能是 IP，强制回退到默认值
		if cert.Mode == "reality" && (cert.ServerName == "" || net.ParseIP(cert.ServerName) != nil) {
			cert.ServerName = "www.cloudflare.com"
		}
		if cert.Email == "" {
			cert.Email = "admin@" + strings.TrimPrefix(cert.ServerName, "*.")
		}
		if cert.RealityPort == 0 {
			cert.RealityPort = 443
		}
		if cert.RealityShortID == "" {
			cert.RealityShortID = randomHex(4)
		}
		if cert.RealityMaxTimeDiff == "" {
			cert.RealityMaxTimeDiff = "1m"
		}
		if cert.UTLSFingerprint == "" {
			cert.UTLSFingerprint = "chrome"
		}
		// Reality 模式状态检查：密钥对是否就绪
		if cert.Mode == "reality" {
			if cert.RealityPrivateKey == "" || cert.RealityPublicKey == "" {
				cert.LastStatus = "missing_key"
				cert.LastMessage = "Reality keypair is required"
			} else if cert.LastStatus == "" || cert.LastStatus == "not_issued" {
				cert.LastStatus = "ready"
				cert.LastMessage = "Reality profile is ready"
			}
		}
		// 非 file/reality 模式自动设置证书存储路径
		if cert.Mode != "file" && cert.Mode != "reality" {
			base := filepath.ToSlash(filepath.Join(stateDir, "certs", cert.ID))
			if cert.CertPath == "" || strings.HasPrefix(cert.CertPath, "/etc/sing-box/cert/") {
				cert.CertPath = filepath.ToSlash(filepath.Join(base, "fullchain.pem"))
			}
			if cert.KeyPath == "" || strings.HasPrefix(cert.KeyPath, "/etc/sing-box/cert/") {
				cert.KeyPath = filepath.ToSlash(filepath.Join(base, "privkey.pem"))
			}
			if cert.LastStatus == "" {
				cert.LastStatus = "not_issued"
			}
		}
		if cert.Mode == "file" && cert.LastStatus == "" {
			cert.LastStatus = "manual"
		}
	}

	// --- 服务字段规范化 ---
	for i := range s.Services {
		svc := &s.Services[i]
		if svc.ID == "" {
			svc.ID = "svc-" + randomHex(6)
		}
		if svc.Listen == "" {
			svc.Listen = "::"
		}
		if svc.Transport == "" {
			svc.Transport = "tcp"
		}
		if svc.TLSMode == "" {
			svc.TLSMode = "standard"
		}
		if svc.RealityHandshakeServer == "" {
			svc.RealityHandshakeServer = "www.cloudflare.com"
		}
		if svc.RealityHandshakePort == 0 {
			svc.RealityHandshakePort = 443
		}
		if svc.RealityShortID == "" {
			svc.RealityShortID = randomHex(4)
		}
		if svc.RealityMaxTimeDiff == "" {
			svc.RealityMaxTimeDiff = "1m"
		}
		if svc.UTLSFingerprint == "" {
			svc.UTLSFingerprint = "chrome"
		}
		// Shadowsocks 默认加密方法
		if svc.Method == "" && svc.Protocol == "shadowsocks" {
			svc.Method = "2022-blake3-aes-128-gcm"
		}
		// 补全用户缺失的凭据
		for j := range svc.Users {
			if svc.Users[j].ID == "" {
				svc.Users[j].ID = "user-" + randomHex(6)
			}
			if svc.Users[j].Name == "" {
				svc.Users[j].Name = "user"
			}
			if svc.Users[j].UUID == "" {
				svc.Users[j].UUID = randomUUID()
			}
			if svc.Users[j].Password == "" {
				svc.Users[j].Password = randomHex(14)
			}
			// VLESS + TCP 默认使用 Vision Flow
			if svc.Protocol == "vless" && svc.Users[j].Flow == "" && svc.Transport == "tcp" {
				svc.Users[j].Flow = "xtls-rprx-vision"
			}
		}
	}
}

// cloneState 通过 JSON 序列化/反序列化实现 AppState 的深拷贝
// 用于 store.mutate() 中先克隆再修改，避免脏写
func cloneState(s AppState) AppState {
	data, _ := json.Marshal(s)
	var out AppState
	_ = json.Unmarshal(data, &out)
	return out
}
