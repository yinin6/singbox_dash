// config_export.go - sing-box 配置生成与导出
//
// 职责：
//   - buildServerConfig()  生成 sing-box 服务端配置（inbounds + DNS + outbounds）
//   - buildClientConfig()  生成指定用户的客户端配置（outbounds + route）
//   - buildSubscription()  生成订阅分享链接（vless:// / trojan:// / hysteria2:// / ss://）
//   - tlsConfig() / realityProfile() / transportConfig()  构建各子配置段
//   - validateSingBoxConfig()  调用 sing-box check 验证配置合法性
//   - certByID() / findUser() / firstUserID()  辅助查找函数
//   - subscriptionHandler / serverConfigHandler / clientConfigHandler  HTTP 处理器
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// serverConfigHandler 导出服务端配置（GET /export/server.json）
func serverConfigHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, buildServerConfig(store.snapshot()))
}

// serverValidateHandler 验证服务端配置是否合法（POST /api/validate/server）
// 先生成配置，再调用 sing-box check 命令验证
func serverValidateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	state := store.snapshot()
	writeJSON(w, validateSingBoxConfig(state.Panel.SingBoxPath, buildServerConfig(state)))
}

// clientConfigHandler 导出指定用户的客户端配置（GET /export/client.json?user={id}）
func clientConfigHandler(w http.ResponseWriter, r *http.Request) {
	state := store.snapshot()
	userID := r.URL.Query().Get("user")
	if userID == "" {
		userID = firstUserID(state) // 未指定用户时使用第一个用户
	}
	cfg, err := buildClientConfig(state, userID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, cfg)
}

// subscriptionHandler 处理订阅链接请求（GET /sub/{token}?user={id}）
// token 用于鉴权，防止未授权访问
func subscriptionHandler(w http.ResponseWriter, r *http.Request) {
	state := store.snapshot()
	token := strings.TrimPrefix(r.URL.Path, "/sub/")
	// 验证订阅令牌
	if token != state.Panel.SubToken {
		http.NotFound(w, r)
		return
	}
	userID := r.URL.Query().Get("user")
	if userID == "" {
		userID = firstUserID(state)
	}
	// 生成纯文本格式的订阅链接列表
	lines := buildSubscription(state, userID)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, line := range lines {
		fmt.Fprintln(w, line.URL)
	}
}

// buildServerConfig 从应用状态构建 sing-box 服务端配置
// 遍历所有已启用的服务，生成对应的 inbound 配置
func buildServerConfig(state AppState) map[string]any {
	inbounds := make([]any, 0, len(state.Services))
	for _, svc := range state.Services {
		if !svc.Enabled {
			continue // 跳过未启用的服务
		}
		inbound := map[string]any{"type": svc.Protocol, "tag": svc.ID, "listen": svc.Listen, "listen_port": svc.Port}
		// 根据协议类型构造用户列表
		switch svc.Protocol {
		case "vless":
			users := make([]any, 0, len(svc.Users))
			for _, u := range svc.Users {
				user := map[string]any{"name": u.Name, "uuid": u.UUID}
				if u.Flow != "" {
					user["flow"] = u.Flow
				}
				users = append(users, user)
			}
			inbound["users"] = users
		case "trojan", "hysteria2":
			users := make([]any, 0, len(svc.Users))
			for _, u := range svc.Users {
				users = append(users, map[string]any{"name": u.Name, "password": u.Password})
			}
			inbound["users"] = users
		case "shadowsocks":
			method := svc.Method
			if method == "" {
				method = "2022-blake3-aes-128-gcm"
			}
			inbound["method"] = method
			if len(svc.Users) > 0 {
				inbound["password"] = svc.Users[0].Password
			}
		}
		// 附加 TLS 配置
		if svc.TLS {
			inbound["tls"] = tlsConfig(state, svc)
		}
		// 附加传输层配置（ws/grpc/http）
		if transport := transportConfig(svc); transport != nil {
			inbound["transport"] = transport
		}
		inbounds = append(inbounds, inbound)
	}
	return map[string]any{
		"log":      map[string]any{"level": "info"},
		"dns":      map[string]any{"strategy": state.Panel.DNSStrategy, "servers": []any{map[string]any{"type": "udp", "tag": "cloudflare", "server": "1.1.1.1"}}},
		"inbounds": inbounds,
		"outbounds": []any{
			map[string]any{"type": "direct", "tag": "direct"},
			map[string]any{"type": "block", "tag": "block"},
		},
	}
}

// buildClientConfig 从应用状态构建指定用户的 sing-box 客户端配置
// 只包含该用户所属的已启用服务
func buildClientConfig(state AppState, userID string) (map[string]any, error) {
	outbounds := []any{map[string]any{"type": "direct", "tag": "direct"}}
	for _, svc := range state.Services {
		if !svc.Enabled {
			continue
		}
		user, ok := findUser(svc, userID)
		if !ok {
			continue // 该用户不在此服务中
		}
		ob := map[string]any{"type": svc.Protocol, "tag": svc.Name, "server": state.Panel.Host, "server_port": svc.Port}
		switch svc.Protocol {
		case "vless":
			ob["uuid"] = user.UUID
			if user.Flow != "" {
				ob["flow"] = user.Flow
			}
		case "trojan", "hysteria2":
			ob["password"] = user.Password
		case "shadowsocks":
			ob["method"] = svc.Method
			ob["password"] = user.Password
		}
		// 客户端 TLS 配置（Reality 或标准 TLS）
		if svc.TLS {
			var tls map[string]any
			if reality, ok := realityProfile(state, svc); ok {
				// Reality 模式：客户端需要公钥、Short ID 和 uTLS 指纹
				tls = map[string]any{
					"enabled":     true,
					"server_name": reality.HandshakeServer,
					"utls":        map[string]any{"enabled": true, "fingerprint": reality.Fingerprint},
					"reality":     map[string]any{"enabled": true, "public_key": reality.PublicKey, "short_id": reality.ShortID},
				}
			} else {
				cert := certByID(state, svc.CertID)
				tls = map[string]any{"enabled": true, "server_name": cert.ServerName}
				if cert.Mode == "self_signed" {
					tls["insecure"] = true // 自签名证书跳过验证
				}
			}
			ob["tls"] = tls
		}
		if transport := transportConfig(svc); transport != nil {
			ob["transport"] = transport
		}
		outbounds = append(outbounds, ob)
	}
	if len(outbounds) == 1 {
		return nil, fmt.Errorf("no enabled service found for user %s", userID)
	}
	return map[string]any{
		"log":       map[string]any{"level": "info"},
		"inbounds":  []any{map[string]any{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}},
		"outbounds": outbounds,
		"route":     map[string]any{"final": outbounds[1].(map[string]any)["tag"]},
	}, nil
}

// buildSubscription 为指定用户生成各协议的分享链接
// 支持 vless://、trojan://、hysteria2://、ss:// 格式
func buildSubscription(state AppState, userID string) []subscriptionLine {
	lines := []subscriptionLine{}
	for _, svc := range state.Services {
		if !svc.Enabled {
			continue
		}
		user, ok := findUser(svc, userID)
		if !ok {
			continue
		}
		name := svc.Name + " - " + user.Name
		switch svc.Protocol {
		case "vless":
			q := url.Values{}
			q.Set("encryption", "none")
			if svc.TLS {
				if reality, ok := realityProfile(state, svc); ok {
					// Reality 链接参数
					q.Set("security", "reality")
					q.Set("sni", reality.HandshakeServer)
					q.Set("fp", reality.Fingerprint)
					q.Set("pbk", reality.PublicKey)
					q.Set("sid", reality.ShortID)
				} else {
					cert := certByID(state, svc.CertID)
					q.Set("security", "tls")
					q.Set("sni", cert.ServerName)
					// 自签名证书附加 SHA256 pin 和验证信息
					if cert.Mode == "self_signed" {
						if pcs, err := certificateSHA256Hex(cert.CertPath); err == nil {
							q.Set("pcs", pcs)
							q.Set("vcn", cert.ServerName)
						}
					}
				}
			}
			if svc.Transport != "tcp" {
				q.Set("type", svc.Transport)
			}
			if svc.Path != "" {
				q.Set("path", svc.Path)
			}
			if user.Flow != "" {
				q.Set("flow", user.Flow)
			}
			lines = append(lines, subscriptionLine{Name: name, URL: fmt.Sprintf("vless://%s@%s:%d?%s#%s", user.UUID, state.Panel.Host, svc.Port, q.Encode(), url.QueryEscape(name))})
		case "trojan":
			q := url.Values{}
			if svc.TLS {
				q.Set("security", "tls")
				q.Set("sni", certByID(state, svc.CertID).ServerName)
			}
			if svc.Transport != "tcp" {
				q.Set("type", svc.Transport)
			}
			if svc.Path != "" {
				q.Set("path", svc.Path)
			}
			lines = append(lines, subscriptionLine{Name: name, URL: fmt.Sprintf("trojan://%s@%s:%d?%s#%s", url.QueryEscape(user.Password), state.Panel.Host, svc.Port, q.Encode(), url.QueryEscape(name))})
		case "hysteria2":
			q := url.Values{}
			if svc.TLS {
				q.Set("sni", certByID(state, svc.CertID).ServerName)
			}
			lines = append(lines, subscriptionLine{Name: name, URL: fmt.Sprintf("hysteria2://%s@%s:%d/?%s#%s", url.QueryEscape(user.Password), state.Panel.Host, svc.Port, q.Encode(), url.QueryEscape(name))})
		case "shadowsocks":
			method := svc.Method
			if method == "" {
				method = "2022-blake3-aes-128-gcm"
			}
			// Shadowsocks 链接格式：ss://base64(method:password)@host:port#name
			cred := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + user.Password))
			lines = append(lines, subscriptionLine{Name: name, URL: fmt.Sprintf("ss://%s@%s:%d#%s", cred, state.Panel.Host, svc.Port, url.QueryEscape(name))})
		}
	}
	return lines
}

// validateSingBoxConfig 将配置写入临时文件，调用 sing-box check 验证合法性
func validateSingBoxConfig(binPath string, cfg map[string]any) map[string]any {
	temp, err := os.CreateTemp("", "singbox_dash_*.json")
	if err != nil {
		return map[string]any{"ok": false, "message": err.Error()}
	}
	defer os.Remove(temp.Name())
	if err := writeConfigFile(temp.Name(), cfg); err != nil {
		return map[string]any{"ok": false, "message": err.Error()}
	}
	return checkSingBoxConfig(binPath, temp.Name())
}

// certificateSHA256Hex 读取证书文件并返回其 SHA256 哈希的十六进制编码
// 用于自签名证书的 pin 验证
func certificateSHA256Hex(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("certificate PEM block not found")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

// tlsConfig 为服务端 inbound 构建 TLS 配置
// 支持 Reality 和标准 TLS（证书文件路径）两种模式
func tlsConfig(state AppState, svc Service) map[string]any {
	if reality, ok := realityProfile(state, svc); ok {
		tls := map[string]any{
			"enabled":     true,
			"server_name": reality.HandshakeServer,
			"reality": map[string]any{
				"enabled":     true,
				"private_key": reality.PrivateKey,
				"short_id":    []string{reality.ShortID},
				"handshake":   map[string]any{"server": reality.HandshakeServer, "server_port": reality.HandshakePort},
			},
		}
		if reality.MaxTimeDiff != "" {
			tls["reality"].(map[string]any)["max_time_difference"] = reality.MaxTimeDiff
		}
		return tls
	}
	cert := certByID(state, svc.CertID)
	return map[string]any{"enabled": true, "server_name": cert.ServerName, "certificate_path": cert.CertPath, "key_path": cert.KeyPath}
}

// realityProfile 从服务关联的证书或服务自身的 TLSMode 提取 Reality 配置
// 优先使用证书级别的 Reality 配置，其次使用服务级别的
func realityProfile(state AppState, svc Service) (RealityProfile, bool) {
	// 证书级别的 Reality 配置（推荐方式，可跨服务复用）
	cert := certByID(state, svc.CertID)
	if cert.Mode == "reality" {
		return RealityProfile{
			HandshakeServer: cert.ServerName,
			HandshakePort:   cert.RealityPort,
			PrivateKey:      cert.RealityPrivateKey,
			PublicKey:       cert.RealityPublicKey,
			ShortID:         cert.RealityShortID,
			MaxTimeDiff:     cert.RealityMaxTimeDiff,
			Fingerprint:     cert.UTLSFingerprint,
		}, true
	}
	// 服务级别的 Reality 配置（兼容旧配置）
	if svc.TLSMode == "reality" {
		return RealityProfile{
			HandshakeServer: svc.RealityHandshakeServer,
			HandshakePort:   svc.RealityHandshakePort,
			PrivateKey:      svc.RealityPrivateKey,
			PublicKey:       svc.RealityPublicKey,
			ShortID:         svc.RealityShortID,
			MaxTimeDiff:     svc.RealityMaxTimeDiff,
			Fingerprint:     svc.UTLSFingerprint,
		}, true
	}
	return RealityProfile{}, false
}

// transportConfig 根据传输层类型构建对应的配置
// 支持 ws / grpc / http，tcp/udp 返回 nil（无需额外配置）
func transportConfig(svc Service) map[string]any {
	switch svc.Transport {
	case "ws":
		out := map[string]any{"type": "ws"}
		if svc.Path != "" {
			out["path"] = svc.Path
		}
		return out
	case "grpc":
		out := map[string]any{"type": "grpc"}
		if svc.Path != "" {
			out["service_name"] = strings.TrimPrefix(svc.Path, "/") // gRPC service name 不带前导斜杠
		}
		return out
	case "http":
		out := map[string]any{"type": "http"}
		if svc.Path != "" {
			out["path"] = svc.Path
		}
		return out
	default:
		return nil
	}
}

// certByID 根据 ID 查找证书，未找到则返回默认证书（使用面板 Host 作为 ServerName）
func certByID(state AppState, id string) Certificate {
	for _, cert := range state.Certificates {
		if cert.ID == id {
			if cert.ServerName == "" {
				cert.ServerName = state.Panel.Host
			}
			return cert
		}
	}
	return Certificate{ServerName: state.Panel.Host, Mode: "file"}
}

// findUser 在服务的用户列表中查找指定 ID 的用户
// 如果只有唯一用户，无论 ID 是否匹配都返回该用户
func findUser(svc Service, userID string) (User, bool) {
	for _, u := range svc.Users {
		if u.ID == userID {
			return u, true
		}
	}
	// 单用户场景：直接返回唯一用户
	if len(svc.Users) == 1 {
		return svc.Users[0], true
	}
	return User{}, false
}

// firstUserID 返回第一个服务中的第一个用户 ID
// 用于未指定用户时的默认选择
func firstUserID(state AppState) string {
	for _, svc := range state.Services {
		if len(svc.Users) > 0 {
			return svc.Users[0].ID
		}
	}
	return ""
}
