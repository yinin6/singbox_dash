// certificate.go - 证书管理
//
// 职责：
//   - HTTP 处理器：创建、删除、签发、状态查询、Reality 密钥对生成
//   - issueCertificate() 根据证书模式（self_signed / reality / ACME / file）执行签发流程
//   - writeSelfSignedCertificate() 生成自签名证书
//   - runACMEScript() 调用 acme.sh 执行 ACME 签发
//   - generateRealityKeypair() 调用 sing-box 生成 Reality 密钥对
//   - refreshCertificateStatus() 从磁盘读取证书并检查有效期
//   - 辅助函数：findACMEScript() / parseEnvLines() / trimCommandOutput()
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// certificateCreateHandler 创建新的证书配置（POST /api/certificate）
// 默认使用 acme_http 模式
func certificateCreateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := store.mutate(func(s *AppState) error {
		id := "cert-" + randomHex(6)
		s.Certificates = append(s.Certificates, Certificate{
			ID:          id,
			Name:        "New Managed Certificate",
			Mode:        "acme_http",
			ServerName:  s.Panel.Host,
			CertPath:    filepath.ToSlash(filepath.Join(stateDir, "certs", id, "fullchain.pem")),
			KeyPath:     filepath.ToSlash(filepath.Join(stateDir, "certs", id, "privkey.pem")),
			Email:       "admin@" + strings.TrimPrefix(s.Panel.Host, "*."),
			CA:          "letsencrypt",
			Challenge:   "http",
			AutoRenew:   true,
			LastStatus:  "not_issued",
			LastMessage: "created",
		})
		return nil
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, store.snapshot())
}

// certificateItemHandler 处理单个证书的操作
// DELETE /api/certificate/{id}                    → 删除证书（同时清理关联服务的 CertID）
// POST   /api/certificate/{id}/issue             → 签发证书
// POST   /api/certificate/{id}/status            → 刷新证书状态
// POST   /api/certificate/{id}/reality-keypair   → 生成 Reality 密钥对
func certificateItemHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/certificate/"), "/"), "/")
	id := ""
	if len(parts) > 0 {
		id = parts[0]
	}
	if id == "" {
		http.NotFound(w, r)
		return
	}
	// 子路由分发
	if len(parts) == 2 && parts[1] == "issue" {
		certificateIssueHandler(w, r, id)
		return
	}
	if len(parts) == 2 && parts[1] == "status" {
		certificateStatusHandler(w, r, id)
		return
	}
	if len(parts) == 2 && parts[1] == "reality-keypair" {
		certificateRealityKeypairHandler(w, r, id)
		return
	}
	switch r.Method {
	case http.MethodDelete:
		err := store.mutate(func(s *AppState) error {
			for i, cert := range s.Certificates {
				if cert.ID == id {
					// 删除证书并清理关联服务的引用
					s.Certificates = append(s.Certificates[:i], s.Certificates[i+1:]...)
					for j := range s.Services {
						if s.Services[j].CertID == id {
							s.Services[j].CertID = ""
						}
					}
					return nil
				}
			}
			return fmt.Errorf("certificate %s not found", id)
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

// certificateIssueHandler 签发指定证书（POST /api/certificate/{id}/issue）
func certificateIssueHandler(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cert, err := issueCertificate(id)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, cert)
}

// certificateStatusHandler 刷新指定证书的状态（POST /api/certificate/{id}/status）
// 从磁盘读取证书文件，检查有效期，更新状态字段
func certificateStatusHandler(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var out Certificate
	err := store.mutate(func(s *AppState) error {
		for i := range s.Certificates {
			if s.Certificates[i].ID == id {
				// Reality 模式不需要刷新文件状态
				if s.Certificates[i].Mode != "reality" {
					refreshCertificateStatus(&s.Certificates[i])
				}
				out = s.Certificates[i]
				return nil
			}
		}
		return fmt.Errorf("certificate %s not found", id)
	})
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, out)
}

// certificateRealityKeypairHandler 为指定证书生成 Reality 密钥对
// POST /api/certificate/{id}/reality-keypair
// 自动将证书模式切换为 reality
func certificateRealityKeypairHandler(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	// 调用 sing-box generate reality-keypair 生成密钥对
	keypair, err := generateRealityKeypair(store.snapshot().Panel.SingBoxPath)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	err = store.mutate(func(s *AppState) error {
		for i := range s.Certificates {
			if s.Certificates[i].ID == id {
				s.Certificates[i].Mode = "reality" // 自动切换为 Reality 模式
				s.Certificates[i].RealityPrivateKey = keypair["private_key"]
				s.Certificates[i].RealityPublicKey = keypair["public_key"]
				if s.Certificates[i].RealityShortID == "" {
					s.Certificates[i].RealityShortID = randomHex(4)
				}
				s.Certificates[i].LastStatus = "ready"
				s.Certificates[i].LastMessage = "Reality keypair generated"
				return nil
			}
		}
		return fmt.Errorf("certificate %s not found", id)
	})
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, store.snapshot())
}

// issueCertificate 根据证书模式执行签发流程
// 支持：self_signed（自签名）、reality（生成密钥对）、acme_*（ACME 签发）、file（不支持自动签发）
func issueCertificate(id string) (Certificate, error) {
	var cert Certificate
	var runErr error
	err := store.mutate(func(s *AppState) error {
		for i := range s.Certificates {
			if s.Certificates[i].ID != id {
				continue
			}
			cert = s.Certificates[i]
			// 非 Reality 模式先确保证书目录存在
			if cert.Mode != "reality" {
				if err := prepareCertificatePaths(cert); err != nil {
					s.Certificates[i].LastStatus = "error"
					s.Certificates[i].LastMessage = err.Error()
					cert = s.Certificates[i]
					return nil
				}
			}
			// 根据模式执行对应的签发操作
			switch cert.Mode {
			case "self_signed":
				runErr = writeSelfSignedCertificate(cert)
			case "reality":
				// Reality 模式需要密钥对，如果没有则自动生成
				if cert.RealityPrivateKey == "" || cert.RealityPublicKey == "" {
					var keypair map[string]string
					keypair, runErr = generateRealityKeypair(s.Panel.SingBoxPath)
					if runErr == nil {
						s.Certificates[i].RealityPrivateKey = keypair["private_key"]
						s.Certificates[i].RealityPublicKey = keypair["public_key"]
					}
				}
			case "acme_http", "acme_tls_alpn", "acme_dns":
				runErr = runACMEScript(cert)
			case "file":
				runErr = fmt.Errorf("manual file certificates cannot be issued automatically")
			default:
				runErr = fmt.Errorf("unsupported certificate mode %s", cert.Mode)
			}
			if runErr != nil {
				s.Certificates[i].LastStatus = "error"
				s.Certificates[i].LastMessage = runErr.Error()
				cert = s.Certificates[i]
				return nil
			}
			// 更新签发状态
			s.Certificates[i].LastStatus = "issued"
			if s.Certificates[i].Mode == "reality" {
				s.Certificates[i].LastStatus = "ready"
				s.Certificates[i].LastMessage = "Reality profile is ready"
			} else {
				s.Certificates[i].LastMessage = "certificate issued"
			}
			s.Certificates[i].LastIssuedAt = time.Now()
			// 非 Reality 模式刷新证书文件状态（检查有效期等）
			if s.Certificates[i].Mode != "reality" {
				refreshCertificateStatus(&s.Certificates[i])
			}
			cert = s.Certificates[i]
			return nil
		}
		return fmt.Errorf("certificate %s not found", id)
	})
	if err != nil {
		return Certificate{}, err
	}
	if runErr != nil {
		return cert, runErr
	}
	return cert, nil
}

// prepareCertificatePaths 验证证书路径参数并创建必要的目录
func prepareCertificatePaths(cert Certificate) error {
	if strings.TrimSpace(cert.ServerName) == "" {
		return errors.New("server name is required")
	}
	if strings.TrimSpace(cert.CertPath) == "" || strings.TrimSpace(cert.KeyPath) == "" {
		return errors.New("certificate and key paths are required")
	}
	// 创建证书和私钥的父目录（权限 0700，仅 owner 可访问）
	if err := os.MkdirAll(filepath.Dir(cert.CertPath), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cert.KeyPath), 0o700); err != nil {
		return err
	}
	return nil
}

// writeSelfSignedCertificate 生成 RSA 2048 位自签名证书，有效期 1 年
// 证书和私钥分别写入 CertPath 和 KeyPath
func writeSelfSignedCertificate(cert Certificate) error {
	// 生成 RSA 私钥
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	// 生成随机序列号
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return err
	}
	now := time.Now()
	tpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cert.ServerName},
		NotBefore:    now.Add(-time.Hour), // 提前 1 小时，避免时钟偏移问题
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}
	// 根据ServerName是IP还是域名设置 SAN
	if ip := net.ParseIP(cert.ServerName); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{cert.ServerName}
	}
	// 自签名：模板同时作为签发者和被签发者
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	// 写入证书文件
	certFile, err := os.OpenFile(cert.CertPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		_ = certFile.Close()
		return err
	}
	if err := certFile.Close(); err != nil {
		return err
	}
	// 写入私钥文件
	keyFile, err := os.OpenFile(cert.KeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		_ = keyFile.Close()
		return err
	}
	return keyFile.Close()
}

// runACMEScript 调用 acme.sh 执行 ACME 证书签发和安装
// 支持 HTTP-01、TLS-ALPN-01、DNS-01 三种验证方式
func runACMEScript(cert Certificate) error {
	acme, err := findACMEScript()
	if err != nil {
		return err
	}
	// 创建 acme.sh 工作目录
	home := filepath.Join(stateDir, "acme")
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	// 构造签发命令参数
	args := []string{"--issue", "-d", cert.ServerName, "--home", home, "--server", cert.CA}
	switch cert.Mode {
	case "acme_http":
		if cert.Webroot != "" {
			args = append(args, "--webroot", cert.Webroot)
		} else {
			args = append(args, "--standalone") // 无 webroot 则使用 standalone 模式
		}
	case "acme_tls_alpn":
		args = append(args, "--alpn")
	case "acme_dns":
		if cert.DNSProvider == "" {
			return errors.New("DNS provider is required for DNS-01")
		}
		args = append(args, "--dns", cert.DNSProvider)
	}
	if cert.Email != "" {
		args = append(args, "--accountemail", cert.Email)
	}
	// 执行签发命令（带 DNS 凭据环境变量，超时 10 分钟）
	if out, err := runCommandWithEnv(acme, args, cert.DNSCredentials); err != nil {
		return fmt.Errorf("%s: %s", err, trimCommandOutput(out))
	}
	// 签发成功后，安装证书到指定路径
	installArgs := []string{"--install-cert", "-d", cert.ServerName, "--home", home, "--server", cert.CA, "--fullchain-file", cert.CertPath, "--key-file", cert.KeyPath}
	if out, err := runCommandWithEnv(acme, installArgs, cert.DNSCredentials); err != nil {
		return fmt.Errorf("%s: %s", err, trimCommandOutput(out))
	}
	return nil
}

// findACMEScript 查找 acme.sh 可执行文件
// 优先搜索 PATH，然后检查 ~/.acme.sh/acme.sh
func findACMEScript() (string, error) {
	if path, err := exec.LookPath("acme.sh"); err == nil {
		return path, nil
	}
	home, _ := os.UserHomeDir()
	candidate := filepath.Join(home, ".acme.sh", "acme.sh")
	if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
		return candidate, nil
	}
	return "", errors.New("acme.sh not found; install it first or use self_signed/manual file mode")
}

// runCommandWithEnv 执行外部命令，附加额外环境变量，超时 10 分钟
func runCommandWithEnv(name string, args []string, envText string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), parseEnvLines(envText)...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), errors.New("command timed out")
	}
	return string(out), err
}

// generateRealityKeypair 调用 sing-box generate reality-keypair 生成密钥对
// 返回包含 private_key 和 public_key 的 map
func generateRealityKeypair(binPath string) (map[string]string, error) {
	bin, err := resolveSingBoxPath(binPath)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "generate", "reality-keypair")
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, errors.New("generate reality keypair timed out")
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %s", err, trimCommandOutput(string(out)))
	}
	// 解析 sing-box 输出中的 PrivateKey 和 PublicKey
	keys := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "PrivateKey:"):
			keys["private_key"] = strings.TrimSpace(strings.TrimPrefix(line, "PrivateKey:"))
		case strings.HasPrefix(line, "PublicKey:"):
			keys["public_key"] = strings.TrimSpace(strings.TrimPrefix(line, "PublicKey:"))
		}
	}
	if keys["private_key"] == "" || keys["public_key"] == "" {
		return nil, fmt.Errorf("unexpected reality keypair output: %s", trimCommandOutput(string(out)))
	}
	return keys, nil
}

// parseEnvLines 将多行环境变量文本解析为 "KEY=VALUE" 格式的字符串切片
// 忽略空行、注释行（# 开头）和不包含 = 的行
func parseEnvLines(text string) []string {
	lines := []string{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

// trimCommandOutput 截断过长的命令输出，只保留最后 1200 个字符
// 用于错误信息展示，避免超长输出
func trimCommandOutput(out string) string {
	out = strings.TrimSpace(out)
	if len(out) > 1200 {
		return out[len(out)-1200:]
	}
	return out
}

// refreshCertificateStatus 从磁盘读取证书文件，解析有效期并更新状态
// 状态转换：
//   - 文件不存在 → missing
//   - PEM 解析失败 → error
//   - 30 天内过期 → renew_due
//   - 其他正常 → valid
func refreshCertificateStatus(cert *Certificate) {
	data, err := os.ReadFile(cert.CertPath)
	if err != nil {
		if cert.LastStatus == "issued" {
			cert.LastStatus = "missing"
			cert.LastMessage = err.Error()
		}
		return
	}
	block, _ := pem.Decode(data)
	if block == nil {
		cert.LastStatus = "error"
		cert.LastMessage = "certificate PEM block not found"
		return
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		cert.LastStatus = "error"
		cert.LastMessage = err.Error()
		return
	}
	cert.ExpiresAt = parsed.NotAfter
	// 30 天内即将过期，标记为需要续签
	if time.Until(parsed.NotAfter) < 30*24*time.Hour {
		cert.LastStatus = "renew_due"
		cert.LastMessage = "certificate expires within 30 days"
		return
	}
	if cert.LastStatus == "" || cert.LastStatus == "missing" || cert.LastStatus == "renew_due" {
		cert.LastStatus = "valid"
	}
	cert.LastMessage = "certificate is present"
}
