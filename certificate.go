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
