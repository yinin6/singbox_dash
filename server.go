// server.go - HTTP 处理器与 sing-box 业务逻辑
//
// 职责：
//   - 处理 /api/state、/api/service、/api/service/{id} 等 REST 接口
//   - 服务创建、删除、Reality 密钥对生成
//   - 工具函数：随机 ID/UUID 生成、端口分配、JSON 响应写入等
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// stateHandler 处理全局状态的读取和整体替换
// GET  /api/state      → 返回当前状态快照
// PUT  /api/state      → 用请求体替换整个状态
func stateHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, store.snapshot())
	case http.MethodPut:
		var next AppState
		if err := json.NewDecoder(r.Body).Decode(&next); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := store.replace(next); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, store.snapshot())
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// serviceCreateHandler 创建一个新的代理服务，带默认配置
// POST /api/service → 新建服务并返回最新状态
func serviceCreateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := store.mutate(func(s *AppState) error {
		// 构造带默认值的新服务
		svc := Service{
			ID:                     "svc-" + randomHex(6),
			Name:                   "New Service",
			Protocol:               "vless",
			Enabled:                true,
			Listen:                 "::",
			Port:                   nextPort(s.Services), // 自动分配下一个可用端口
			TLS:                    true,
			TLSMode:                "standard",
			Transport:              "tcp",
			RealityHandshakeServer: "www.cloudflare.com",
			RealityHandshakePort:   443,
			RealityShortID:         randomHex(4),
			RealityMaxTimeDiff:     "1m",
			UTLSFingerprint:        "chrome",
			Users: []User{
				{ID: "user-" + randomHex(6), Name: "default", UUID: randomUUID(), Password: randomHex(14), Flow: "xtls-rprx-vision"},
			},
		}
		// 如果已有证书，自动关联第一个证书
		if len(s.Certificates) > 0 {
			svc.CertID = s.Certificates[0].ID
		}
		s.Services = append(s.Services, svc)
		return nil
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, store.snapshot())
}

// serviceItemHandler 处理单个服务的操作
// DELETE /api/service/{id}                  → 删除指定服务
// POST   /api/service/{id}/reality-keypair  → 生成 Reality 密钥对（转发到子处理器）
func serviceItemHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/service/"), "/"), "/")
	id := ""
	if len(parts) > 0 {
		id = parts[0]
	}
	if id == "" {
		http.NotFound(w, r)
		return
	}
	// 路由到 Reality 密钥对生成子处理器
	if len(parts) == 2 && parts[1] == "reality-keypair" {
		serviceRealityKeypairHandler(w, r, id)
		return
	}
	switch r.Method {
	case http.MethodDelete:
		err := store.mutate(func(s *AppState) error {
			for i, svc := range s.Services {
				if svc.ID == id {
					s.Services = append(s.Services[:i], s.Services[i+1:]...)
					return nil
				}
			}
			return fmt.Errorf("service %s not found", id)
		})
		if err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeJSON(w, store.snapshot())
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// serviceRealityKeypairHandler 为指定服务生成 Reality 密钥对
// POST /api/service/{id}/reality-keypair
func serviceRealityKeypairHandler(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// 调用 sing-box generate reality-keypair 命令生成密钥
	keypair, err := generateRealityKeypair(store.snapshot().Panel.SingBoxPath)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	err = store.mutate(func(s *AppState) error {
		for i := range s.Services {
			if s.Services[i].ID == id {
				s.Services[i].RealityPrivateKey = keypair["private_key"]
				s.Services[i].RealityPublicKey = keypair["public_key"]
				if s.Services[i].RealityShortID == "" {
					s.Services[i].RealityShortID = randomHex(4)
				}
				return nil
			}
		}
		return fmt.Errorf("service %s not found", id)
	})
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, store.snapshot())
}

// nextPort 从 8443 开始查找第一个未被使用的端口号
// 遍历已有服务的端口，返回最小可用端口
func nextPort(services []Service) int {
	used := map[int]bool{}
	for _, svc := range services {
		used[svc.Port] = true
	}
	for port := 8443; port < math.MaxUint16; port++ {
		if !used[port] {
			return port
		}
	}
	return 9443
}

// randomHex 生成 n 字节长度的随机十六进制字符串
// 如果随机数生成失败，回退到时间戳
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

// randomUUID 生成符合 RFC 4122 v4 规范的随机 UUID
func randomUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "00000000-0000-4000-8000-" + randomHex(6)
	}
	// 设置版本号 (4) 和变体位 (10xx)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// writeJSON 将任意值序列化为带缩进的 JSON 并写入响应
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// writeError 将错误信息以 JSON 格式写入响应
func writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

// runtimeFilePath 清理文件路径，空字符串直接返回
// 用于处理 sing-box 运行时相关文件路径
func runtimeFilePath(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	return filepath.Clean(path)
}
