package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

// ecsLogger writes ECS-compatible ndJSON, as every platform service does.
func ecsLogger() *slog.Logger {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) > 0 {
				return a
			}
			switch a.Key {
			case slog.TimeKey:
				a.Key = "@timestamp"
			case slog.LevelKey:
				return slog.String("log.level", strings.ToLower(a.Value.String()))
			case slog.MessageKey:
				a.Key = "message"
			}
			return a
		},
	})
	return slog.New(handler).With("ecs.version", "1.6.0", "service.name", "voice-gateway")
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// clientCertificate reads the gateway's key pair for each dial: cert-manager renews it while the gateway runs,
// and murmur-agent refuses it once it has expired. A pair that cannot be read fails that session's dial.
func clientCertificate(certFile, keyFile string) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("gateway certificate: %w", err)
		}
		return &cert, nil
	}
}

func loadConfig() (Config, error) {
	origin := os.Getenv("GATEWAY_ORIGIN")
	if origin == "" {
		return Config{}, errors.New("GATEWAY_ORIGIN must be set, e.g. https://mtls.example.org")
	}
	certFile, keyFile := env("GATEWAY_CERT", "/certs/tls.crt"), env("GATEWAY_KEY", "/certs/tls.key")
	// Read here so a missing or broken pair stops the start, and again for every session (clientCertificate)
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return Config{}, fmt.Errorf("gateway certificate: %w", err)
	}
	bundle, err := os.ReadFile(env("GATEWAY_MURMUR_CA", "/trust/ca-cert.pem"))
	if err != nil {
		return Config{}, fmt.Errorf("Murmur's CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundle) {
		return Config{}, errors.New("no certificates in Murmur's CA bundle")
	}
	name := os.Getenv("GATEWAY_MURMUR_NAME")
	if name == "" {
		return Config{}, errors.New("GATEWAY_MURMUR_NAME must be set to the name on Murmur's certificate")
	}
	return Config{
		Origin:          origin,
		TraefikIdentity: env("GATEWAY_TRAEFIK_IDENTITY", "traefik.traefik-system.serviceaccount.identity.linkerd.cluster.local"),
		MurmurAddr:      env("GATEWAY_MURMUR_ADDR", "murmur.app-mumble.svc.cluster.local:64738"),
		MurmurTLS: &tls.Config{
			MinVersion:           tls.VersionTLS12,
			ServerName:           name,
			RootCAs:              roots,
			GetClientCertificate: clientCertificate(certFile, keyFile),
		},
	}, nil
}

func newMux(gateway, ready http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("GET /ws", gateway)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.Handle("GET /readyz", ready)
	return mux
}

// readyz answers mumblermapi's health check: 204 once this pod's Linkerd proxy is ready at proxyReady, without which
// Traefik's identity never reaches the gateway and every browser is refused; an empty proxyReady is not checked.
// Murmur is never dialled for it: every browser's session comes from this pod's address, and Murmur bans an
// address that connects too often.
func readyz(proxyReady string, client *http.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if proxyReady != "" {
			resp, err := client.Get(proxyReady)
			if err != nil {
				http.Error(w, "no Linkerd proxy", http.StatusServiceUnavailable)
				return
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				http.Error(w, "Linkerd proxy not ready", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func main() {
	log := ecsLogger()
	cfg, err := loadConfig()
	if err != nil {
		log.Error("cannot start", "error", err.Error())
		os.Exit(1)
	}
	gateway, err := NewGateway(cfg, log)
	if err != nil {
		log.Error("cannot start", "error", err.Error())
		os.Exit(1)
	}
	server := &http.Server{
		Addr:              env("GATEWAY_LISTEN", ":8080"),
		Handler:           newMux(gateway, readyz(env("GATEWAY_PROXY_READY", "http://127.0.0.1:4191/ready"), &http.Client{Timeout: time.Second})),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Info("voice gateway listening", "addr", server.Addr, "murmur", cfg.MurmurAddr)
	if err := server.ListenAndServe(); err != nil {
		log.Error("stopped", "error", err.Error())
		os.Exit(1)
	}
}
