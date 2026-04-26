package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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
	Host              string `json:"host"`
	DNSStrategy       string `json:"dns_strategy"`
	SubToken          string `json:"sub_token"`
	SingBoxPath       string `json:"sing_box_path"`
	RuntimeConfigPath string `json:"runtime_config_path"`
	RuntimePIDPath    string `json:"runtime_pid_path"`
	RuntimeLogPath    string `json:"runtime_log_path"`
	AutoRestart       bool   `json:"auto_restart"`
}

type Certificate struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Mode           string    `json:"mode"`
	ServerName     string    `json:"server_name"`
	CertPath       string    `json:"cert_path"`
	KeyPath        string    `json:"key_path"`
	Email          string    `json:"email"`
	CA             string    `json:"ca"`
	Challenge      string    `json:"challenge"`
	Webroot        string    `json:"webroot"`
	DNSProvider    string    `json:"dns_provider"`
	DNSCredentials string    `json:"dns_credentials"`
	AutoRenew      bool      `json:"auto_renew"`
	LastStatus     string    `json:"last_status"`
	LastMessage    string    `json:"last_message"`
	LastIssuedAt   time.Time `json:"last_issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
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
	Flow     string `json:"flow"`
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
	mux.HandleFunc("/api/validate/server", serverValidateHandler)
	mux.HandleFunc("/api/runtime/apply", runtimeApplyHandler)
	mux.HandleFunc("/api/runtime/status", runtimeStatusHandler)
	mux.HandleFunc("/api/runtime/stop", runtimeStopHandler)
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
				Name:      "VLESS WS TLS",
				Protocol:  "vless",
				Enabled:   true,
				Listen:    "::",
				Port:      443,
				TLS:       true,
				CertID:    certID,
				Transport: "http",
				Path:      "/vless",
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
	for i := range s.Certificates {
		cert := &s.Certificates[i]
		if cert.ID == "" {
			cert.ID = "cert-" + randomHex(6)
		}
		if cert.Mode == "" {
			cert.Mode = "file"
		}
		if cert.Mode == "acme" {
			cert.Mode = "acme_http"
		}
		if cert.CA == "" {
			cert.CA = "letsencrypt"
		}
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
		if cert.Email == "" {
			cert.Email = "admin@" + strings.TrimPrefix(cert.ServerName, "*.")
		}
		if cert.Mode != "file" {
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
			if svc.Protocol == "vless" && svc.Users[j].Flow == "" && svc.Transport == "tcp" {
				svc.Users[j].Flow = "xtls-rprx-vision"
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
				refreshCertificateStatus(&s.Certificates[i])
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

func serverConfigHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, buildServerConfig(store.snapshot()))
}

func serverValidateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	state := store.snapshot()
	result := validateSingBoxConfig(state.Panel.SingBoxPath, buildServerConfig(state))
	writeJSON(w, result)
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
	panel := store.snapshot().Panel
	status := stopRuntime(panel)
	writeJSON(w, status)
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
				user := map[string]any{"name": u.Name, "uuid": u.UUID}
				if u.Flow != "" {
					user["flow"] = u.Flow
				}
				users = append(users, user)
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
			"servers":  []any{map[string]any{"type": "udp", "tag": "cloudflare", "server": "1.1.1.1"}},
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
			if err := prepareCertificatePaths(cert); err != nil {
				s.Certificates[i].LastStatus = "error"
				s.Certificates[i].LastMessage = err.Error()
				cert = s.Certificates[i]
				return nil
			}
			switch cert.Mode {
			case "self_signed":
				runErr = writeSelfSignedCertificate(cert)
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
			s.Certificates[i].LastMessage = "certificate issued"
			s.Certificates[i].LastIssuedAt = time.Now()
			refreshCertificateStatus(&s.Certificates[i])
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
		return map[string]any{
			"ok":      false,
			"message": err.Error(),
		}
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
		return map[string]any{
			"running":     false,
			"message":     "not running",
			"config_path": panel.RuntimeConfigPath,
			"log_path":    panel.RuntimeLogPath,
			"log_tail":    tailFile(panel.RuntimeLogPath, 4000),
		}
	}
	return map[string]any{
		"running":     true,
		"pid":         pids[0],
		"pids":        pids,
		"message":     "running",
		"config_path": panel.RuntimeConfigPath,
		"log_path":    panel.RuntimeLogPath,
		"log_tail":    tailFile(panel.RuntimeLogPath, 4000),
	}
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
		Subject: pkix.Name{
			CommonName: cert.ServerName,
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{cert.ServerName},
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

	installArgs := []string{
		"--install-cert", "-d", cert.ServerName,
		"--home", home,
		"--server", cert.CA,
		"--fullchain-file", cert.CertPath,
		"--key-file", cert.KeyPath,
	}
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

func tlsConfig(state AppState, svc Service) map[string]any {
	cert := certByID(state, svc.CertID)
	tls := map[string]any{
		"enabled":     true,
		"server_name": cert.ServerName,
	}
	tls["certificate_path"] = cert.CertPath
	tls["key_path"] = cert.KeyPath
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
    .card textarea { min-height: 84px; }
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
    .cert-status { color: var(--muted); font-size: 12px; }
    .cert-status strong { color: var(--ink); }
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
      <button onclick="validateServer()">检测配置</button>
      <button class="secondary" onclick="applyRuntime()">应用到 sing-box</button>
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
          <h2>运行时</h2>
          <button onclick="refreshRuntimeStatus()">状态</button>
        </div>
        <div class="stack">
          <label>sing-box 路径 <input id="singBoxPath" oninput="updatePanel()" placeholder="sing-box"></label>
          <label>运行配置 <input id="runtimeConfigPath" oninput="updatePanel()" placeholder="data/runtime/server.json"></label>
          <label>PID 文件 <input id="runtimePIDPath" oninput="updatePanel()" placeholder="data/runtime/sing-box.pid"></label>
          <label>日志文件 <input id="runtimeLogPath" oninput="updatePanel()" placeholder="data/runtime/sing-box.log"></label>
          <label class="row"><input id="autoRestart" type="checkbox" onchange="updatePanel()"> 应用后自动重启</label>
          <div class="row">
            <button class="secondary" onclick="applyRuntime()">应用</button>
            <button class="danger" onclick="stopRuntime()">停止</button>
          </div>
          <div class="mono" id="runtimeStatus">未查询</div>
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
              <option value="http">HTTP / H2</option>
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
      $("singBoxPath").value = state.panel.sing_box_path || "sing-box";
      $("runtimeConfigPath").value = state.panel.runtime_config_path || "data/runtime/server.json";
      $("runtimePIDPath").value = state.panel.runtime_pid_path || "data/runtime/sing-box.pid";
      $("runtimeLogPath").value = state.panel.runtime_log_path || "data/runtime/sing-box.log";
      $("autoRestart").checked = state.panel.auto_restart !== false;
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
        const expires = cert.expires_at && !cert.expires_at.startsWith("0001-") ? new Date(cert.expires_at).toLocaleString() : "未读取";
        card.innerHTML =
          '<div class="row between">' +
            '<div class="cert-status"><strong>' + escapeHTML(cert.last_status || "unknown") + '</strong><br>' + escapeHTML(cert.last_message || "") + '<br>到期：' + escapeHTML(expires) + '</div>' +
            '<div class="row"><button onclick="issueCert(\'' + cert.id + '\')">签发/续期</button><button onclick="refreshCert(\'' + cert.id + '\')">刷新</button></div>' +
          '</div>' +
          '<div class="grid">' +
            '<label>名称 <input value="' + escapeAttr(cert.name || "") + '" data-cert="' + cert.id + '" data-field="name"></label>' +
            '<label>模式 <select data-cert="' + cert.id + '" data-field="mode">' +
              '<option value="file">手动文件</option><option value="self_signed">自签名</option><option value="acme_http">ACME HTTP-01</option><option value="acme_tls_alpn">ACME TLS-ALPN-01</option><option value="acme_dns">ACME DNS-01</option>' +
            '</select></label>' +
            '<label>服务名 <input value="' + escapeAttr(cert.server_name || "") + '" data-cert="' + cert.id + '" data-field="server_name"></label>' +
            '<label>邮箱 <input value="' + escapeAttr(cert.email || "") + '" data-cert="' + cert.id + '" data-field="email"></label>' +
            '<label>CA <select data-cert="' + cert.id + '" data-field="ca">' +
              '<option value="letsencrypt">Lets Encrypt</option><option value="zerossl">ZeroSSL</option><option value="buypass">Buypass</option><option value="ssl.com">SSL.com</option>' +
            '</select></label>' +
            '<label>Webroot <input value="' + escapeAttr(cert.webroot || "") + '" data-cert="' + cert.id + '" data-field="webroot" placeholder="/var/www/html"></label>' +
            '<label>DNS Provider <input value="' + escapeAttr(cert.dns_provider || "") + '" data-cert="' + cert.id + '" data-field="dns_provider" placeholder="dns_cf / dns_ali / dns_dp"></label>' +
            '<label>证书路径 <input value="' + escapeAttr(cert.cert_path || "") + '" data-cert="' + cert.id + '" data-field="cert_path"></label>' +
            '<label>私钥路径 <input value="' + escapeAttr(cert.key_path || "") + '" data-cert="' + cert.id + '" data-field="key_path"></label>' +
          '</div>' +
          '<label>DNS 环境变量 <textarea data-cert="' + cert.id + '" data-field="dns_credentials" placeholder="CF_Token=...\\nCF_Account_ID=...">' + escapeHTML(cert.dns_credentials || "") + '</textarea></label>' +
          '<label class="row"><input type="checkbox" data-cert="' + cert.id + '" data-field="auto_renew"> 自动续期</label>' +
          '<button class="danger" onclick="deleteCert(\'' + cert.id + '\')">删除证书</button>';
        $("certList").appendChild(card);
        card.querySelector('[data-field="mode"]').value = cert.mode || "file";
        card.querySelector('[data-field="ca"]').value = cert.ca || "letsencrypt";
        card.querySelector('[data-field="auto_renew"]').checked = !!cert.auto_renew;
      }
      $("certList").querySelectorAll("input, select").forEach(el => {
        el.oninput = () => {
          const cert = state.certificates.find(c => c.id === el.dataset.cert);
          cert[el.dataset.field] = el.type === "checkbox" ? el.checked : el.value;
          renderEditor();
        };
      });
      $("certList").querySelectorAll("textarea").forEach(el => {
        el.oninput = () => {
          const cert = state.certificates.find(c => c.id === el.dataset.cert);
          cert[el.dataset.field] = el.value;
        };
      });
    }

    async function deleteCert(id) {
      state = await fetch("/api/certificate/" + encodeURIComponent(id), {method: "DELETE"}).then(r => r.json());
      render();
    }

    async function issueCert(id) {
      await saveState({render: false});
      const res = await fetch("/api/certificate/" + encodeURIComponent(id) + "/issue", {method: "POST"});
      const body = await res.json();
      if (!res.ok) $("status").textContent = body.error || "证书签发失败";
      await loadState();
    }

    async function refreshCert(id) {
      await saveState({render: false});
      await fetch("/api/certificate/" + encodeURIComponent(id) + "/status", {method: "POST"});
      await loadState();
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
            '<label>VLESS Flow <select data-user="' + user.id + '" data-field="flow">' +
              '<option value="">none</option><option value="xtls-rprx-vision">xtls-rprx-vision</option>' +
            '</select></label>' +
          '</div>' +
          '<button class="danger" onclick="deleteUser(\'' + user.id + '\')">删除用户</button>';
        $("userList").appendChild(card);
        card.querySelector('[data-field="flow"]').value = user.flow || "";
      }
      $("userList").querySelectorAll("input, select").forEach(el => {
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
      state.panel.sing_box_path = $("singBoxPath").value;
      state.panel.runtime_config_path = $("runtimeConfigPath").value;
      state.panel.runtime_pid_path = $("runtimePIDPath").value;
      state.panel.runtime_log_path = $("runtimeLogPath").value;
      state.panel.auto_restart = $("autoRestart").checked;
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
      svc.users.push({id: "user-" + rand(), name: "user", uuid: crypto.randomUUID(), password: rand() + rand(), flow: svc.protocol === "vless" && svc.transport === "tcp" ? "xtls-rprx-vision" : ""});
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

    async function validateServer() {
      await saveState({render: false});
      const result = await fetch("/api/validate/server", {method: "POST"}).then(r => r.json());
      $("status").textContent = result.ok ? "服务端配置检测通过" : "服务端配置检测失败";
      if (currentTab !== "preview") setTab("preview");
      $("previewType").value = "server";
      $("preview").value = (result.message || "") + "\n\n" + (result.output || "");
    }

    async function applyRuntime() {
      await saveState({render: false});
      const result = await fetch("/api/runtime/apply", {method: "POST"}).then(r => r.json());
      $("status").textContent = result.ok ? "已应用到 sing-box" : "应用失败";
      showRuntimeResult(result);
    }

    async function stopRuntime() {
      const result = await fetch("/api/runtime/stop", {method: "POST"}).then(r => r.json());
      $("status").textContent = "sing-box 已停止";
      showRuntimeResult(result);
    }

    async function refreshRuntimeStatus() {
      const result = await fetch("/api/runtime/status").then(r => r.json());
      showRuntimeResult(result);
    }

    function showRuntimeResult(result) {
      $("runtimeStatus").textContent =
        "状态: " + (result.running ? "运行中" : "未运行") +
        (result.pid ? "\nPID: " + result.pid : "") +
        "\n消息: " + (result.message || "") +
        "\n配置: " + (result.config_path || state.panel.runtime_config_path || "") +
        "\n日志: " + (result.log_path || state.panel.runtime_log_path || "");
      if (currentTab !== "preview") setTab("preview");
      $("preview").value = JSON.stringify(result, null, 2) + (result.log_tail ? "\n\n--- log tail ---\n" + result.log_tail : "");
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
