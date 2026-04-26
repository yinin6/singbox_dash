package main

import (
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"time"
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
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Mode               string    `json:"mode"`
	ServerName         string    `json:"server_name"`
	CertPath           string    `json:"cert_path"`
	KeyPath            string    `json:"key_path"`
	Email              string    `json:"email"`
	CA                 string    `json:"ca"`
	Challenge          string    `json:"challenge"`
	Webroot            string    `json:"webroot"`
	DNSProvider        string    `json:"dns_provider"`
	DNSCredentials     string    `json:"dns_credentials"`
	AutoRenew          bool      `json:"auto_renew"`
	LastStatus         string    `json:"last_status"`
	LastMessage        string    `json:"last_message"`
	LastIssuedAt       time.Time `json:"last_issued_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	RealityPort        int       `json:"reality_port"`
	RealityPrivateKey  string    `json:"reality_private_key"`
	RealityPublicKey   string    `json:"reality_public_key"`
	RealityShortID     string    `json:"reality_short_id"`
	RealityMaxTimeDiff string    `json:"reality_max_time_diff"`
	UTLSFingerprint    string    `json:"utls_fingerprint"`
}

type Service struct {
	ID                     string `json:"id"`
	Name                   string `json:"name"`
	Protocol               string `json:"protocol"`
	Enabled                bool   `json:"enabled"`
	Listen                 string `json:"listen"`
	Port                   int    `json:"port"`
	TLS                    bool   `json:"tls"`
	TLSMode                string `json:"tls_mode"`
	CertID                 string `json:"cert_id"`
	Transport              string `json:"transport"`
	Path                   string `json:"path"`
	Method                 string `json:"method"`
	RealityHandshakeServer string `json:"reality_handshake_server"`
	RealityHandshakePort   int    `json:"reality_handshake_port"`
	RealityPrivateKey      string `json:"reality_private_key"`
	RealityPublicKey       string `json:"reality_public_key"`
	RealityShortID         string `json:"reality_short_id"`
	RealityMaxTimeDiff     string `json:"reality_max_time_diff"`
	UTLSFingerprint        string `json:"utls_fingerprint"`
	Users                  []User `json:"users"`
}

type User struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	UUID     string `json:"uuid"`
	Password string `json:"password"`
	Flow     string `json:"flow"`
}

type Store struct {
	mu    RWMutex
	state AppState
}

type subscriptionLine struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type RealityProfile struct {
	HandshakeServer string
	HandshakePort   int
	PrivateKey      string
	PublicKey       string
	ShortID         string
	MaxTimeDiff     string
	Fingerprint     string
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
		if cert.Mode == "reality" {
			if cert.RealityPrivateKey == "" || cert.RealityPublicKey == "" {
				cert.LastStatus = "missing_key"
				cert.LastMessage = "Reality keypair is required"
			} else if cert.LastStatus == "" || cert.LastStatus == "not_issued" {
				cert.LastStatus = "ready"
				cert.LastMessage = "Reality profile is ready"
			}
		}
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
