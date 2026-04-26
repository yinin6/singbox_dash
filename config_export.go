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
