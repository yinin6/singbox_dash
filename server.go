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

func runtimeFilePath(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	return filepath.Clean(path)
}
