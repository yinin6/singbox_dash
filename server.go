package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

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

func serviceCreateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := store.mutate(func(s *AppState) error {
		svc := Service{
			ID:                     "svc-" + randomHex(6),
			Name:                   "New Service",
			Protocol:               "vless",
			Enabled:                true,
			Listen:                 "::",
			Port:                   nextPort(s.Services),
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

func serviceRealityKeypairHandler(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
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

func certificateStatusHandler(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var out Certificate
	err := store.mutate(func(s *AppState) error {
		for i := range s.Certificates {
			if s.Certificates[i].ID == id {
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

func certificateRealityKeypairHandler(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	keypair, err := generateRealityKeypair(store.snapshot().Panel.SingBoxPath)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	err = store.mutate(func(s *AppState) error {
		for i := range s.Certificates {
			if s.Certificates[i].ID == id {
				s.Certificates[i].Mode = "reality"
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

func serverConfigHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, buildServerConfig(store.snapshot()))
}

func serverValidateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	state := store.snapshot()
	writeJSON(w, validateSingBoxConfig(state.Panel.SingBoxPath, buildServerConfig(state)))
}

func runtimeApplyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, applyRuntimeConfig(store.snapshot()))
}

func runtimeStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, runtimeStatus(store.snapshot().Panel))
}

func runtimeStopHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, stopRuntime(store.snapshot().Panel))
}

func clientConfigHandler(w http.ResponseWriter, r *http.Request) {
	state := store.snapshot()
	userID := r.URL.Query().Get("user")
	if userID == "" {
		userID = firstUserID(state)
	}
	cfg, err := buildClientConfig(state, userID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, cfg)
}

func subscriptionHandler(w http.ResponseWriter, r *http.Request) {
	state := store.snapshot()
	token := strings.TrimPrefix(r.URL.Path, "/sub/")
	if token != state.Panel.SubToken {
		http.NotFound(w, r)
		return
	}
	userID := r.URL.Query().Get("user")
	if userID == "" {
		userID = firstUserID(state)
	}
	lines := buildSubscription(state, userID)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, line := range lines {
		fmt.Fprintln(w, line.URL)
	}
}

func buildServerConfig(state AppState) map[string]any {
	inbounds := make([]any, 0, len(state.Services))
	for _, svc := range state.Services {
		if !svc.Enabled {
			continue
		}
		inbound := map[string]any{"type": svc.Protocol, "tag": svc.ID, "listen": svc.Listen, "listen_port": svc.Port}
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
		if svc.TLS {
			inbound["tls"] = tlsConfig(state, svc)
		}
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

func buildClientConfig(state AppState, userID string) (map[string]any, error) {
	outbounds := []any{map[string]any{"type": "direct", "tag": "direct"}}
	for _, svc := range state.Services {
		if !svc.Enabled {
			continue
		}
		user, ok := findUser(svc, userID)
		if !ok {
			continue
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
		if svc.TLS {
			var tls map[string]any
			if reality, ok := realityProfile(state, svc); ok {
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
					tls["insecure"] = true
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
					q.Set("security", "reality")
					q.Set("sni", reality.HandshakeServer)
					q.Set("fp", reality.Fingerprint)
					q.Set("pbk", reality.PublicKey)
					q.Set("sid", reality.ShortID)
				} else {
					cert := certByID(state, svc.CertID)
					q.Set("security", "tls")
					q.Set("sni", cert.ServerName)
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
			cred := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + user.Password))
			lines = append(lines, subscriptionLine{Name: name, URL: fmt.Sprintf("ss://%s@%s:%d#%s", cred, state.Panel.Host, svc.Port, url.QueryEscape(name))})
		}
	}
	return lines
}

func issueCertificate(id string) (Certificate, error) {
	var cert Certificate
	var runErr error
	err := store.mutate(func(s *AppState) error {
		for i := range s.Certificates {
			if s.Certificates[i].ID != id {
				continue
			}
			cert = s.Certificates[i]
			if cert.Mode != "reality" {
				if err := prepareCertificatePaths(cert); err != nil {
					s.Certificates[i].LastStatus = "error"
					s.Certificates[i].LastMessage = err.Error()
					cert = s.Certificates[i]
					return nil
				}
			}
			switch cert.Mode {
			case "self_signed":
				runErr = writeSelfSignedCertificate(cert)
			case "reality":
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
			s.Certificates[i].LastStatus = "issued"
			if s.Certificates[i].Mode == "reality" {
				s.Certificates[i].LastStatus = "ready"
				s.Certificates[i].LastMessage = "Reality profile is ready"
			} else {
				s.Certificates[i].LastMessage = "certificate issued"
			}
			s.Certificates[i].LastIssuedAt = time.Now()
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

func applyRuntimeConfig(state AppState) map[string]any {
	panel := state.Panel
	cfg := buildServerConfig(state)
	if err := writeConfigFile(panel.RuntimeConfigPath, cfg); err != nil {
		return map[string]any{"ok": false, "stage": "write", "message": err.Error()}
	}
	check := checkSingBoxConfig(panel.SingBoxPath, panel.RuntimeConfigPath)
	if ok, _ := check["ok"].(bool); !ok {
		check["stage"] = "check"
		check["config_path"] = panel.RuntimeConfigPath
		return check
	}
	if panel.AutoRestart {
		stopRuntime(panel)
		start := startRuntime(panel)
		start["stage"] = "start"
		start["config_path"] = panel.RuntimeConfigPath
		return start
	}
	status := runtimeStatus(panel)
	status["ok"] = true
	status["stage"] = "write"
	status["message"] = "config written and validated; auto restart is disabled"
	status["config_path"] = panel.RuntimeConfigPath
	return status
}

func writeConfigFile(path string, cfg map[string]any) error {
	if path == "" {
		return errors.New("config path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func checkSingBoxConfig(binPath string, configPath string) map[string]any {
	bin, err := resolveSingBoxPath(binPath)
	if err != nil {
		return map[string]any{"ok": false, "message": err.Error()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "check", "-c", configPath)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return map[string]any{"ok": false, "message": "sing-box check timed out", "output": string(out)}
	}
	if err != nil {
		return map[string]any{"ok": false, "message": err.Error(), "output": string(out)}
	}
	return map[string]any{"ok": true, "message": "sing-box check passed", "output": string(out)}
}

func startRuntime(panel PanelSettings) map[string]any {
	bin, err := resolveSingBoxPath(panel.SingBoxPath)
	if err != nil {
		return map[string]any{"ok": false, "message": err.Error()}
	}
	if err := os.MkdirAll(filepath.Dir(panel.RuntimePIDPath), 0o700); err != nil {
		return map[string]any{"ok": false, "message": err.Error()}
	}
	if err := os.MkdirAll(filepath.Dir(panel.RuntimeLogPath), 0o700); err != nil {
		return map[string]any{"ok": false, "message": err.Error()}
	}
	logFile, err := os.OpenFile(panel.RuntimeLogPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return map[string]any{"ok": false, "message": err.Error()}
	}
	cmd := exec.Command(bin, "run", "-c", panel.RuntimeConfigPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return map[string]any{"ok": false, "message": err.Error()}
	}
	_ = logFile.Close()
	if err := os.WriteFile(panel.RuntimePIDPath, []byte(strconv.Itoa(cmd.Process.Pid)), 0o600); err != nil {
		_ = cmd.Process.Kill()
		return map[string]any{"ok": false, "message": err.Error()}
	}
	_ = cmd.Process.Release()
	time.Sleep(300 * time.Millisecond)
	status := runtimeStatus(panel)
	if running, _ := status["running"].(bool); !running {
		status["ok"] = false
		status["message"] = "sing-box started but exited immediately; check runtime log"
		status["log_tail"] = tailFile(panel.RuntimeLogPath, 4000)
		return status
	}
	status["ok"] = true
	status["message"] = "sing-box is running"
	return status
}

func stopRuntime(panel PanelSettings) map[string]any {
	pids := runtimePIDs(panel)
	if len(pids) == 0 {
		return map[string]any{"ok": true, "running": false, "message": "sing-box is not managed by this panel"}
	}
	for _, pid := range pids {
		proc, err := os.FindProcess(pid)
		if err == nil {
			_ = proc.Signal(os.Interrupt)
			for i := 0; i < 20; i++ {
				if !processRunning(pid) {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if processRunning(pid) {
				_ = proc.Kill()
			}
		}
	}
	_ = os.Remove(panel.RuntimePIDPath)
	return map[string]any{"ok": true, "running": false, "pids": pids, "message": "sing-box stopped"}
}

func runtimeStatus(panel PanelSettings) map[string]any {
	pids := runtimePIDs(panel)
	if len(pids) == 0 {
		_ = os.Remove(panel.RuntimePIDPath)
		return map[string]any{"running": false, "message": "not running", "config_path": panel.RuntimeConfigPath, "log_path": panel.RuntimeLogPath, "log_tail": tailFile(panel.RuntimeLogPath, 4000)}
	}
	return map[string]any{"running": true, "pid": pids[0], "pids": pids, "message": "running", "config_path": panel.RuntimeConfigPath, "log_path": panel.RuntimeLogPath, "log_tail": tailFile(panel.RuntimeLogPath, 4000)}
}

func resolveSingBoxPath(path string) (string, error) {
	if path == "" {
		path = "sing-box"
	}
	if strings.ContainsRune(path, filepath.Separator) || strings.HasPrefix(path, ".") {
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			return path, nil
		}
		return "", fmt.Errorf("sing-box binary not found at %s", path)
	}
	bin, err := exec.LookPath(path)
	if err != nil {
		return "", fmt.Errorf("%s command not found", path)
	}
	return bin, nil
}

func readRuntimePID(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

func runtimePIDs(panel PanelSettings) []int {
	seen := map[int]bool{}
	pids := []int{}
	if pid, err := readRuntimePID(panel.RuntimePIDPath); err == nil && processRunning(pid) {
		seen[pid] = true
		pids = append(pids, pid)
	}
	for _, pid := range findProcessesByConfig(panel.RuntimeConfigPath) {
		if !seen[pid] && processRunning(pid) {
			seen[pid] = true
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)
	return pids
}

func findProcessesByConfig(configPath string) []int {
	matches := []int{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return matches
	}
	absConfig, _ := filepath.Abs(configPath)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if err != nil || len(data) == 0 {
			continue
		}
		cmdline := strings.ReplaceAll(string(data), "\x00", " ")
		if strings.Contains(cmdline, "sing-box") &&
			strings.Contains(cmdline, " run ") &&
			(strings.Contains(cmdline, configPath) || (absConfig != "" && strings.Contains(cmdline, absConfig))) {
			matches = append(matches, pid)
		}
	}
	return matches
}

func processRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	status, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err == nil {
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "State:") {
				return !strings.Contains(line, "Z (zombie)")
			}
		}
		return true
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(nil) == nil
}

func tailFile(path string, limit int) string {
	if path == "" || limit <= 0 {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if len(data) > limit {
		data = data[len(data)-limit:]
	}
	return string(data)
}

func prepareCertificatePaths(cert Certificate) error {
	if strings.TrimSpace(cert.ServerName) == "" {
		return errors.New("server name is required")
	}
	if strings.TrimSpace(cert.CertPath) == "" || strings.TrimSpace(cert.KeyPath) == "" {
		return errors.New("certificate and key paths are required")
	}
	if err := os.MkdirAll(filepath.Dir(cert.CertPath), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(cert.KeyPath), 0o700); err != nil {
		return err
	}
	return nil
}

func writeSelfSignedCertificate(cert Certificate) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return err
	}
	now := time.Now()
	tpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cert.ServerName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(cert.ServerName); ip != nil {
		tpl.IPAddresses = []net.IP{ip}
	} else {
		tpl.DNSNames = []string{cert.ServerName}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
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

func runACMEScript(cert Certificate) error {
	acme, err := findACMEScript()
	if err != nil {
		return err
	}
	home := filepath.Join(stateDir, "acme")
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	args := []string{"--issue", "-d", cert.ServerName, "--home", home, "--server", cert.CA}
	switch cert.Mode {
	case "acme_http":
		if cert.Webroot != "" {
			args = append(args, "--webroot", cert.Webroot)
		} else {
			args = append(args, "--standalone")
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
	if out, err := runCommandWithEnv(acme, args, cert.DNSCredentials); err != nil {
		return fmt.Errorf("%s: %s", err, trimCommandOutput(out))
	}
	installArgs := []string{"--install-cert", "-d", cert.ServerName, "--home", home, "--server", cert.CA, "--fullchain-file", cert.CertPath, "--key-file", cert.KeyPath}
	if out, err := runCommandWithEnv(acme, installArgs, cert.DNSCredentials); err != nil {
		return fmt.Errorf("%s: %s", err, trimCommandOutput(out))
	}
	return nil
}

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

func trimCommandOutput(out string) string {
	out = strings.TrimSpace(out)
	if len(out) > 1200 {
		return out[len(out)-1200:]
	}
	return out
}

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

func certificateSHA256Hex(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", errors.New("certificate PEM block not found")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

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

func realityProfile(state AppState, svc Service) (RealityProfile, bool) {
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
			out["service_name"] = strings.TrimPrefix(svc.Path, "/")
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

func findUser(svc Service, userID string) (User, bool) {
	for _, u := range svc.Users {
		if u.ID == userID {
			return u, true
		}
	}
	if len(svc.Users) == 1 {
		return svc.Users[0], true
	}
	return User{}, false
}

func firstUserID(state AppState) string {
	for _, svc := range state.Services {
		if len(svc.Users) > 0 {
			return svc.Users[0].ID
		}
	}
	return ""
}

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

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

func randomUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "00000000-0000-4000-8000-" + randomHex(6)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
