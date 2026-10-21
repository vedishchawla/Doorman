// Package mtls provides a certificate-authenticated, reload-aware HTTP transport.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// Config identifies the CA and client certificate files used by the transport.
type Config struct {
	CAFile         string
	ClientCertFile string
	ClientKeyFile  string
}

type fileState struct {
	modTime time.Time
	size    int64
}

// NewTransport creates an HTTP transport that verifies server certificates
// against CAFile and reloads the CA and client certificate when files change.
func NewTransport(cfg Config) (*http.Transport, error) {
	if cfg.CAFile == "" || cfg.ClientCertFile == "" || cfg.ClientKeyFile == "" {
		return nil, fmt.Errorf("CA, client certificate, and client key files are required")
	}
	if _, err := loadCAPool(cfg.CAFile); err != nil {
		return nil, err
	}
	if _, err := loadCertificate(cfg.ClientCertFile, cfg.ClientKeyFile); err != nil {
		return nil, err
	}

	var mu sync.Mutex
	var caState, certState fileState
	var roots *x509.CertPool
	var cert *tls.Certificate
	reload := func() error {
		mu.Lock()
		defer mu.Unlock()
		caInfo, err := os.Stat(cfg.CAFile)
		if err != nil {
			return fmt.Errorf("stat CA file: %w", err)
		}
		certInfo, err := os.Stat(cfg.ClientCertFile)
		if err != nil {
			return fmt.Errorf("stat client certificate: %w", err)
		}
		keyInfo, err := os.Stat(cfg.ClientKeyFile)
		if err != nil {
			return fmt.Errorf("stat client key: %w", err)
		}
		nextCA := fileState{caInfo.ModTime(), caInfo.Size()}
		modTime := certInfo.ModTime()
		if keyInfo.ModTime().After(modTime) {
			modTime = keyInfo.ModTime()
		}
		nextCert := fileState{modTime, certInfo.Size() + keyInfo.Size()}
		if roots == nil || nextCA != caState {
			roots, err = loadCAPool(cfg.CAFile)
			if err != nil {
				return err
			}
			caState = nextCA
		}
		if cert == nil || nextCert != certState {
			cert, err = loadCertificate(cfg.ClientCertFile, cfg.ClientKeyFile)
			if err != nil {
				return err
			}
			certState = nextCert
		}
		return nil
	}
	if err := reload(); err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // VerifyConnection performs certificate and hostname validation with reloaded roots.
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if err := reload(); err != nil {
				return nil, err
			}
			mu.Lock()
			defer mu.Unlock()
			return cert, nil
		},
		VerifyConnection: func(state tls.ConnectionState) error {
			if err := reload(); err != nil {
				return err
			}
			mu.Lock()
			pool := roots
			mu.Unlock()
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("backend presented no certificate")
			}
			_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
				Roots:         pool,
				Intermediates: intermediates(state.PeerCertificates[1:]),
				DNSName:       state.ServerName,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			})
			return err
		},
	}
	return &http.Transport{TLSClientConfig: tlsConfig}, nil
}

func loadCAPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("CA file contains no certificates")
	}
	return pool, nil
}

func loadCertificate(certFile, keyFile string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client certificate: %w", err)
	}
	return &cert, nil
}

func intermediates(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}
