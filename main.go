package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	addr      = "127.0.0.1:8088"
	stateDir  = "data"
	stateFile = "data/state.json"
)

type AppState struct {
	Panel        PanelSettings `json:"panel"`
	Certificates []Certificate `json:"certificates"`
	Services     []Service     `json:"services"`
	UpdatedAt    time.Time     `json:"updated_at"`
}

type PanelSettings struct {
	Host        string `json:"host"`
	DNSStrategy string `json:"dns_strategy"`
	SubToken    string `json:"sub_token"`
}

type Certificate struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Mode       string `json:"mode"`
	ServerName string `json:"server_name"`
	CertPath   string `json:"cert_path"`
	KeyPath    string `json:"key_path"`
	Email      string `json:"email"`
}

type Service struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Protocol  string `json:"protocol"`
	Enabled   bool   `json:"enabled"`
	Listen    string `json:"listen"`
	Port      int    `json:"port"`
	TLS       bool   `json:"tls"`
	CertID    string `json:"cert_id"`
	Transport string `json:"transport"`
	Path      string `json:"path"`
	Method    string `json:"method"`
	Users     []User `json:"users"`
}

type User struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	UUID     string `json:"uuid"`
	Password string `json:"password"`
}

type Store struct {
	mu    sync.RWMutex
	state AppState
}

type subscriptionLine struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

var store = &Store{}

func main() {
	if err := store.load(); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/api/state", stateHandler)
	mux.HandleFunc("/api/service", serviceCreateHandler)
	mux.HandleFunc("/api/service/", serviceItemHandler)
	mux.HandleFunc("/api/certificate", certificateCreateHandler)
	mux.HandleFunc("/api/certificate/", certificateItemHandler)
	mux.HandleFunc("/export/server.json", serverConfigHandler)
	mux.HandleFunc("/export/client.json", clientConfigHandler)
	mux.HandleFunc("/sub/", subscriptionHandler)

	log.Printf("singbox_dash listening on http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := os.Stat(stateFile); errors.Is(err, os.ErrNotExist) {
		s.state = defaultState()
		return s.saveLocked()
	}

	data, err := os.ReadFile(stateFile)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &s.state); err != nil {
		return err
	}
	normalizeState(&s.state)
	return nil
}

func (s *Store) snapshot() AppState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneState(s.state)
}

func (s *Store) replace(next AppState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	normalizeState(&next)
	next.UpdatedAt = time.Now()
	s.state = next
	return s.saveLocked()
}

func (s *Store) mutate(fn func(*AppState) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.state)
	if err := fn(&next); err != nil {
		return err
	}
	normalizeState(&next)
	next.UpdatedAt = time.Now()
	s.state = next
	return s.saveLocked()
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(stateFile, data, 0o600)
}

func defaultState() AppState {
	token := randomHex(16)
	certID := "cert-default"
	return AppState{
		Panel: PanelSettings{
			Host:        "example.com",
			DNSStrategy: "prefer_ipv4",
			SubToken:    token,
		},
		Certificates: []Certificate{
			{
				ID:         certID,
				Name:       "Default TLS",
				Mode:       "file",
				ServerName: "example.com",
				CertPath:   "/etc/sing-box/cert/fullchain.pem",
				KeyPath:    "/etc/sing-box/cert/privkey.pem",
				Email:      "admin@example.com",
			},
		},
		Services: []Service{
			{
				ID:        "svc-vless-ws",
				Name:      "VLESS WS TLS",
				Protocol:  "vless",
				Enabled:   true,
				Listen:    "::",
				Port:      443,
				TLS:       true,
				CertID:    certID,
				Transport: "ws",
				Path:      "/vless",
				Users: []User{
					{ID: "user-main", Name: "main", UUID: randomUUID(), Password: randomHex(12)},
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

func normalizeState(s *AppState) {
	if s.Panel.Host == "" {
		s.Panel.Host = "example.com"
	}
	if s.Panel.DNSStrategy == "" {
		s.Panel.DNSStrategy = "prefer_ipv4"
	}
	if s.Panel.SubToken == "" {
		s.Panel.SubToken = randomHex(16)
	}
	for i := range s.Certificates {
		if s.Certificates[i].ID == "" {
			s.Certificates[i].ID = "cert-" + randomHex(6)
		}
		if s.Certificates[i].Mode == "" {
			s.Certificates[i].Mode = "file"
		}
	}
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
		if svc.Method == "" && svc.Protocol == "shadowsocks" {
			svc.Method = "2022-blake3-aes-128-gcm"
		}
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
		}
	}
}

func cloneState(s AppState) AppState {
	data, _ := json.Marshal(s)
	var out AppState
	_ = json.Unmarshal(data, &out)
	return out
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pageTemplate.Execute(w, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

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
			ID:        "svc-" + randomHex(6),
			Name:      "New Service",
			Protocol:  "vless",
			Enabled:   true,
			Listen:    "::",
			Port:      nextPort(s.Services),
			TLS:       true,
			Transport: "tcp",
			Users: []User{
				{ID: "user-" + randomHex(6), Name: "default", UUID: randomUUID(), Password: randomHex(14)},
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
	id := strings.TrimPrefix(r.URL.Path, "/api/service/")
	if id == "" {
		http.NotFound(w, r)
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

func certificateCreateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := store.mutate(func(s *AppState) error {
		s.Certificates = append(s.Certificates, Certificate{
			ID:         "cert-" + randomHex(6),
			Name:       "New Certificate",
			Mode:       "file",
			ServerName: s.Panel.Host,
			CertPath:   "/etc/sing-box/cert/fullchain.pem",
			KeyPath:    "/etc/sing-box/cert/privkey.pem",
		})
		return nil
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, store.snapshot())
}

func certificateItemHandler(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/certificate/")
	if id == "" {
		http.NotFound(w, r)
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

func serverConfigHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, buildServerConfig(store.snapshot()))
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
		inbound := map[string]any{
			"type":        svc.Protocol,
			"tag":         svc.ID,
			"listen":      svc.Listen,
			"listen_port": svc.Port,
		}
		switch svc.Protocol {
		case "vless":
			users := make([]any, 0, len(svc.Users))
			for _, u := range svc.Users {
				users = append(users, map[string]any{"name": u.Name, "uuid": u.UUID})
			}
			inbound["users"] = users
		case "trojan":
			users := make([]any, 0, len(svc.Users))
			for _, u := range svc.Users {
				users = append(users, map[string]any{"name": u.Name, "password": u.Password})
			}
			inbound["users"] = users
		case "hysteria2":
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
		"log": map[string]any{"level": "info"},
		"dns": map[string]any{
			"strategy": state.Panel.DNSStrategy,
			"servers":  []any{map[string]any{"tag": "cloudflare", "address": "1.1.1.1"}},
		},
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
		ob := map[string]any{
			"type":        svc.Protocol,
			"tag":         svc.Name,
			"server":      state.Panel.Host,
			"server_port": svc.Port,
		}
		switch svc.Protocol {
		case "vless":
			ob["uuid"] = user.UUID
		case "trojan", "hysteria2":
			ob["password"] = user.Password
		case "shadowsocks":
			ob["method"] = svc.Method
			ob["password"] = user.Password
		}
		if svc.TLS {
			cert := certByID(state, svc.CertID)
			ob["tls"] = map[string]any{
				"enabled":     true,
				"server_name": cert.ServerName,
			}
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
		"log": map[string]any{"level": "info"},
		"inbounds": []any{
			map[string]any{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080},
		},
		"outbounds": outbounds,
		"route": map[string]any{
			"final": outbounds[1].(map[string]any)["tag"],
		},
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
				q.Set("security", "tls")
				q.Set("sni", certByID(state, svc.CertID).ServerName)
			}
			if svc.Transport != "tcp" {
				q.Set("type", svc.Transport)
			}
			if svc.Path != "" {
				q.Set("path", svc.Path)
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

func tlsConfig(state AppState, svc Service) map[string]any {
	cert := certByID(state, svc.CertID)
	tls := map[string]any{
		"enabled":     true,
		"server_name": cert.ServerName,
	}
	if cert.Mode == "acme" {
		tls["acme"] = map[string]any{
			"domain": cert.ServerName,
			"email":  cert.Email,
		}
	} else {
		tls["certificate_path"] = cert.CertPath
		tls["key_path"] = cert.KeyPath
	}
	return tls
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
		return map[string]any{"type": "http"}
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

func fileURL(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

var _ = fileURL

var pageTemplate = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>singbox_dash</title>
  <style>
    :root {
      color-scheme: light;
      --ink: #17202a;
      --muted: #5e6a75;
      --line: #d7dde3;
      --paper: #f6f7f9;
      --panel: #ffffff;
      --accent: #0d7c66;
      --accent-2: #2f5c9f;
      --danger: #b42318;
      --shadow: 0 8px 24px rgba(25, 36, 50, .08);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--paper);
      color: var(--ink);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      letter-spacing: 0;
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 18px 24px;
      border-bottom: 1px solid var(--line);
      background: var(--panel);
      position: sticky;
      top: 0;
      z-index: 5;
    }
    h1 { font-size: 20px; margin: 0; }
    h2 { font-size: 15px; margin: 0 0 12px; }
    h3 { font-size: 14px; margin: 0 0 10px; }
    main {
      display: grid;
      grid-template-columns: minmax(280px, 360px) 1fr;
      gap: 18px;
      padding: 18px;
      max-width: 1480px;
      margin: 0 auto;
    }
    aside, section, .card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
    }
    aside, section { padding: 16px; }
    .stack { display: grid; gap: 12px; }
    .row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .between { justify-content: space-between; }
    .grid { display: grid; grid-template-columns: repeat(2, minmax(180px, 1fr)); gap: 12px; }
    label { display: grid; gap: 6px; color: var(--muted); font-size: 12px; }
    input, select, textarea {
      width: 100%;
      min-height: 36px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      color: var(--ink);
      padding: 8px 10px;
      font: inherit;
    }
    textarea { min-height: 360px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; resize: vertical; }
    button, a.button {
      border: 1px solid var(--line);
      background: #fff;
      color: var(--ink);
      border-radius: 6px;
      padding: 8px 11px;
      min-height: 36px;
      cursor: pointer;
      text-decoration: none;
      font: inherit;
      display: inline-flex;
      align-items: center;
      gap: 7px;
    }
    button.primary { background: var(--accent); color: #fff; border-color: var(--accent); }
    button.secondary { color: var(--accent-2); }
    button.danger { color: var(--danger); }
    .card { padding: 13px; box-shadow: none; }
    .service-list { display: grid; gap: 10px; }
    .service-list button {
      justify-content: space-between;
      width: 100%;
      text-align: left;
      border-color: var(--line);
    }
    .service-list button.active { border-color: var(--accent); outline: 2px solid rgba(13, 124, 102, .12); }
    .pill {
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      border-radius: 999px;
      padding: 2px 8px;
      background: #eef3f2;
      color: var(--accent);
      font-size: 12px;
    }
    .muted { color: var(--muted); }
    .tabs { display: flex; gap: 8px; border-bottom: 1px solid var(--line); margin: -4px -4px 14px; padding: 0 4px 10px; }
    .tabs button.active { background: #eef3f2; border-color: var(--accent); }
    .hidden { display: none; }
    .mono { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12px; overflow-wrap: anywhere; }
    .status { min-height: 20px; color: var(--accent); font-size: 13px; }
    @media (max-width: 900px) {
      header { align-items: flex-start; flex-direction: column; }
      main { grid-template-columns: 1fr; padding: 12px; }
      .grid { grid-template-columns: 1fr; }
      .row { align-items: stretch; }
      button, a.button { justify-content: center; }
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>singbox_dash</h1>
      <div class="muted">sing-box 服务端组合、客户端配置与订阅输出</div>
    </div>
    <div class="row">
      <button class="primary" onclick="saveState()">保存</button>
      <a class="button" href="/export/server.json" target="_blank">服务端 JSON</a>
      <a class="button" id="clientLink" href="/export/client.json" target="_blank">客户端 JSON</a>
    </div>
  </header>

  <main>
    <aside class="stack">
      <section>
        <h2>全局</h2>
        <div class="stack">
          <label>域名或 IP <input id="host" oninput="updatePanel()" placeholder="example.com"></label>
          <label>DNS 策略
            <select id="dnsStrategy" onchange="updatePanel()">
              <option value="prefer_ipv4">prefer_ipv4</option>
              <option value="prefer_ipv6">prefer_ipv6</option>
              <option value="ipv4_only">ipv4_only</option>
              <option value="ipv6_only">ipv6_only</option>
            </select>
          </label>
          <label>订阅 Token <input id="subToken" oninput="updatePanel()"></label>
          <div class="mono" id="subUrl"></div>
        </div>
      </section>
      <section>
        <div class="row between">
          <h2>服务</h2>
          <button onclick="addService()">＋</button>
        </div>
        <div class="service-list" id="serviceList"></div>
      </section>
      <section>
        <div class="row between">
          <h2>证书</h2>
          <button onclick="addCert()">＋</button>
        </div>
        <div class="stack" id="certList"></div>
      </section>
    </aside>

    <section>
      <div class="tabs">
        <button id="tabEdit" class="active" onclick="setTab('edit')">配置</button>
        <button id="tabPreview" onclick="setTab('preview')">预览</button>
      </div>
      <div id="editPane" class="stack">
        <div class="row between">
          <h2 id="serviceTitle">服务详情</h2>
          <button class="danger" onclick="deleteCurrentService()">删除服务</button>
        </div>
        <div class="grid">
          <label>名称 <input id="svcName" oninput="updateService()"></label>
          <label>协议
            <select id="svcProtocol" onchange="updateService()">
              <option value="vless">VLESS</option>
              <option value="trojan">Trojan</option>
              <option value="hysteria2">Hysteria2</option>
              <option value="shadowsocks">Shadowsocks</option>
            </select>
          </label>
          <label>监听地址 <input id="svcListen" oninput="updateService()"></label>
          <label>端口 <input id="svcPort" type="number" min="1" max="65535" oninput="updateService()"></label>
          <label>传输
            <select id="svcTransport" onchange="updateService()">
              <option value="tcp">TCP</option>
              <option value="ws">WebSocket</option>
              <option value="grpc">gRPC</option>
              <option value="http">HTTP</option>
              <option value="udp">UDP</option>
            </select>
          </label>
          <label>路径 / gRPC Service <input id="svcPath" oninput="updateService()" placeholder="/proxy"></label>
          <label>证书
            <select id="svcCert" onchange="updateService()"></select>
          </label>
          <label>Shadowsocks 加密 <input id="svcMethod" oninput="updateService()" placeholder="2022-blake3-aes-128-gcm"></label>
        </div>
        <div class="row">
          <label class="row"><input id="svcEnabled" type="checkbox" onchange="updateService()"> 启用</label>
          <label class="row"><input id="svcTLS" type="checkbox" onchange="updateService()"> TLS</label>
        </div>
        <div class="row between">
          <h3>用户</h3>
          <button onclick="addUser()">＋</button>
        </div>
        <div class="stack" id="userList"></div>
      </div>
      <div id="previewPane" class="hidden stack">
        <div class="row between">
          <h2>导出预览</h2>
          <div class="status" id="status"></div>
        </div>
        <div class="grid">
          <label>用户
            <select id="previewUser" onchange="refreshPreview()"></select>
          </label>
          <label>类型
            <select id="previewType" onchange="refreshPreview()">
              <option value="server">服务端配置</option>
              <option value="client">客户端配置</option>
              <option value="sub">订阅链接</option>
            </select>
          </label>
        </div>
        <textarea id="preview" readonly></textarea>
      </div>
    </section>
  </main>

  <script>
    let state = null;
    let currentServiceId = "";
    let currentTab = "edit";

    const $ = (id) => document.getElementById(id);

    async function loadState() {
      state = await fetch("/api/state").then(r => r.json());
      currentServiceId = state.services?.[0]?.id || "";
      render();
    }

    async function saveState(options) {
      const shouldRender = !options || options.render !== false;
      normalizeClientState();
      state = await fetch("/api/state", {
        method: "PUT",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify(state)
      }).then(r => r.json());
      $("status").textContent = "已保存 " + new Date().toLocaleTimeString();
      if (shouldRender) render();
    }

    async function addService() {
      state = await fetch("/api/service", {method: "POST"}).then(r => r.json());
      currentServiceId = state.services[state.services.length - 1].id;
      render();
    }

    async function addCert() {
      state = await fetch("/api/certificate", {method: "POST"}).then(r => r.json());
      render();
    }

    async function deleteCurrentService() {
      if (!currentServiceId) return;
      state = await fetch("/api/service/" + encodeURIComponent(currentServiceId), {method: "DELETE"}).then(r => r.json());
      currentServiceId = state.services?.[0]?.id || "";
      render();
    }

    function render() {
      $("host").value = state.panel.host || "";
      $("dnsStrategy").value = state.panel.dns_strategy || "prefer_ipv4";
      $("subToken").value = state.panel.sub_token || "";
      $("subUrl").textContent = location.origin + "/sub/" + state.panel.sub_token + "?user=" + encodeURIComponent(firstUserId());
      $("clientLink").href = "/export/client.json?user=" + encodeURIComponent(firstUserId());
      renderServices();
      renderCerts();
      renderEditor();
      renderPreviewUsers();
      if (currentTab === "preview") refreshPreview();
    }

    function renderServices() {
      $("serviceList").innerHTML = "";
      for (const svc of state.services || []) {
        const btn = document.createElement("button");
        btn.className = svc.id === currentServiceId ? "active" : "";
        btn.onclick = () => { currentServiceId = svc.id; renderEditor(); renderServices(); };
        btn.innerHTML = '<span>' + escapeHTML(svc.name || svc.protocol) + '<br><span class="muted">' + svc.protocol + " : " + svc.port + '</span></span><span class="pill">' + (svc.enabled ? "on" : "off") + "</span>";
        $("serviceList").appendChild(btn);
      }
    }

    function renderCerts() {
      $("certList").innerHTML = "";
      for (const cert of state.certificates || []) {
        const card = document.createElement("div");
        card.className = "card stack";
        card.innerHTML =
          '<div class="grid">' +
            '<label>名称 <input value="' + escapeAttr(cert.name || "") + '" data-cert="' + cert.id + '" data-field="name"></label>' +
            '<label>模式 <select data-cert="' + cert.id + '" data-field="mode">' +
              '<option value="file">file</option><option value="acme">acme</option>' +
            '</select></label>' +
            '<label>服务名 <input value="' + escapeAttr(cert.server_name || "") + '" data-cert="' + cert.id + '" data-field="server_name"></label>' +
            '<label>邮箱 <input value="' + escapeAttr(cert.email || "") + '" data-cert="' + cert.id + '" data-field="email"></label>' +
            '<label>证书路径 <input value="' + escapeAttr(cert.cert_path || "") + '" data-cert="' + cert.id + '" data-field="cert_path"></label>' +
            '<label>私钥路径 <input value="' + escapeAttr(cert.key_path || "") + '" data-cert="' + cert.id + '" data-field="key_path"></label>' +
          '</div>' +
          '<button class="danger" onclick="deleteCert(\'' + cert.id + '\')">删除证书</button>';
        $("certList").appendChild(card);
        card.querySelector('[data-field="mode"]').value = cert.mode || "file";
      }
      $("certList").querySelectorAll("input, select").forEach(el => {
        el.oninput = () => {
          const cert = state.certificates.find(c => c.id === el.dataset.cert);
          cert[el.dataset.field] = el.value;
          renderEditor();
        };
      });
    }

    async function deleteCert(id) {
      state = await fetch("/api/certificate/" + encodeURIComponent(id), {method: "DELETE"}).then(r => r.json());
      render();
    }

    function renderEditor() {
      const svc = currentService();
      if (!svc) {
        $("editPane").classList.add("hidden");
        return;
      }
      $("editPane").classList.remove("hidden");
      $("serviceTitle").textContent = svc.name || "服务详情";
      $("svcName").value = svc.name || "";
      $("svcProtocol").value = svc.protocol || "vless";
      $("svcListen").value = svc.listen || "::";
      $("svcPort").value = svc.port || 443;
      $("svcTransport").value = svc.transport || "tcp";
      $("svcPath").value = svc.path || "";
      $("svcMethod").value = svc.method || "";
      $("svcEnabled").checked = !!svc.enabled;
      $("svcTLS").checked = !!svc.tls;
      $("svcCert").innerHTML = '<option value="">未选择</option>' + (state.certificates || []).map(c => '<option value="' + c.id + '">' + escapeHTML(c.name || c.id) + '</option>').join("");
      $("svcCert").value = svc.cert_id || "";
      renderUsers(svc);
    }

    function renderUsers(svc) {
      $("userList").innerHTML = "";
      for (const user of svc.users || []) {
        const card = document.createElement("div");
        card.className = "card stack";
        card.innerHTML =
          '<div class="grid">' +
            '<label>用户名 <input value="' + escapeAttr(user.name || "") + '" data-user="' + user.id + '" data-field="name"></label>' +
            '<label>UUID <input value="' + escapeAttr(user.uuid || "") + '" data-user="' + user.id + '" data-field="uuid"></label>' +
            '<label>密码 <input value="' + escapeAttr(user.password || "") + '" data-user="' + user.id + '" data-field="password"></label>' +
          '</div>' +
          '<button class="danger" onclick="deleteUser(\'' + user.id + '\')">删除用户</button>';
        $("userList").appendChild(card);
      }
      $("userList").querySelectorAll("input").forEach(el => {
        el.oninput = () => {
          const user = currentService().users.find(u => u.id === el.dataset.user);
          user[el.dataset.field] = el.value;
          renderPreviewUsers();
        };
      });
    }

    function updatePanel() {
      state.panel.host = $("host").value;
      state.panel.dns_strategy = $("dnsStrategy").value;
      state.panel.sub_token = $("subToken").value;
      $("subUrl").textContent = location.origin + "/sub/" + state.panel.sub_token + "?user=" + encodeURIComponent(firstUserId());
    }

    function updateService() {
      const svc = currentService();
      if (!svc) return;
      svc.name = $("svcName").value;
      svc.protocol = $("svcProtocol").value;
      svc.listen = $("svcListen").value;
      svc.port = Number($("svcPort").value || 0);
      svc.transport = $("svcTransport").value;
      svc.path = $("svcPath").value;
      svc.method = $("svcMethod").value;
      svc.cert_id = $("svcCert").value;
      svc.enabled = $("svcEnabled").checked;
      svc.tls = $("svcTLS").checked;
      renderServices();
    }

    function addUser() {
      const svc = currentService();
      svc.users = svc.users || [];
      svc.users.push({id: "user-" + rand(), name: "user", uuid: crypto.randomUUID(), password: rand() + rand()});
      renderUsers(svc);
      renderPreviewUsers();
    }

    function deleteUser(id) {
      const svc = currentService();
      svc.users = (svc.users || []).filter(u => u.id !== id);
      renderUsers(svc);
      renderPreviewUsers();
    }

    function setTab(tab) {
      currentTab = tab;
      $("tabEdit").classList.toggle("active", tab === "edit");
      $("tabPreview").classList.toggle("active", tab === "preview");
      $("editPane").classList.toggle("hidden", tab !== "edit");
      $("previewPane").classList.toggle("hidden", tab !== "preview");
      if (tab === "preview") refreshPreview();
    }

    async function refreshPreview() {
      await saveState({render: false});
      const type = $("previewType").value;
      const user = $("previewUser").value || firstUserId();
      if (type === "server") {
        $("preview").value = await fetch("/export/server.json").then(r => r.text());
      } else if (type === "client") {
        $("preview").value = await fetch("/export/client.json?user=" + encodeURIComponent(user)).then(r => r.text());
      } else {
        const sub = location.origin + "/sub/" + state.panel.sub_token + "?user=" + encodeURIComponent(user);
        const body = await fetch(sub).then(r => r.text());
        $("preview").value = sub + "\n\n" + body;
      }
    }

    function renderPreviewUsers() {
      const selected = $("previewUser").value;
      const users = [];
      for (const svc of state.services || []) {
        for (const user of svc.users || []) users.push({id: user.id, name: user.name + " / " + svc.name});
      }
      $("previewUser").innerHTML = users.map(u => '<option value="' + u.id + '">' + escapeHTML(u.name) + '</option>').join("");
      $("previewUser").value = users.some(u => u.id === selected) ? selected : firstUserId();
    }

    function currentService() {
      return (state.services || []).find(s => s.id === currentServiceId);
    }

    function firstUserId() {
      for (const svc of state.services || []) {
        if (svc.users?.length) return svc.users[0].id;
      }
      return "";
    }

    function normalizeClientState() {
      state.updated_at = new Date().toISOString();
      for (const svc of state.services || []) {
        svc.port = Number(svc.port || 0);
        svc.users = svc.users || [];
      }
    }

    function rand() {
      return Math.random().toString(16).slice(2, 10);
    }

    function escapeHTML(value) {
      return String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }

    function escapeAttr(value) {
      return escapeHTML(value);
    }

    loadState();
  </script>
</body>
</html>`))
