package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTransportPresentsClientCertificateAndReloads(t *testing.T) {
	dir := t.TempDir()
	caCert, caKey := makeCA(t, dir)
	serverCert, serverKey := makeLeaf(t, dir, caCert, caKey, "localhost", x509.ExtKeyUsageServerAuth)
	clientCert, clientKey := makeLeaf(t, dir, caCert, caKey, "proxy-client", x509.ExtKeyUsageClientAuth)
	reloadedCert, reloadedKey := makeLeaf(t, dir, caCert, caKey, "proxy-client-reloaded", x509.ExtKeyUsageClientAuth)
	writePEM(t, filepath.Join(dir, "ca.crt"), "CERTIFICATE", caCert.Raw)
	writePEM(t, filepath.Join(dir, "server.crt"), "CERTIFICATE", serverCert.Raw)
	writePEM(t, filepath.Join(dir, "server.key"), "EC PRIVATE KEY", clientKeyBytes(t, serverKey))
	writePEM(t, filepath.Join(dir, "client.crt"), "CERTIFICATE", clientCert.Raw)
	writePEM(t, filepath.Join(dir, "client.key"), "EC PRIVATE KEY", clientKeyBytes(t, clientKey))

	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	clientNames := make(chan string, 2)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) != 1 {
			t.Errorf("expected one client certificate")
		}
		clientNames <- r.TLS.PeerCertificates[0].Subject.CommonName
		w.WriteHeader(http.StatusOK)
	}))
	serverConfig := tlsConfigForTest(pool, serverCert, serverKey)
	server.TLS = &serverConfig
	server.StartTLS()
	defer server.Close()

	transport, err := NewTransport(Config{
		CAFile: filepath.Join(dir, "ca.crt"), ClientCertFile: filepath.Join(dir, "client.crt"), ClientKeyFile: filepath.Join(dir, "client.key"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	time.Sleep(10 * time.Millisecond)
	writePEM(t, filepath.Join(dir, "client.crt"), "CERTIFICATE", reloadedCert.Raw)
	writePEM(t, filepath.Join(dir, "client.key"), "EC PRIVATE KEY", clientKeyBytes(t, reloadedKey))
	transport.CloseIdleConnections()
	resp, err = client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := <-clientNames; got != "proxy-client" {
		t.Fatalf("expected initial client certificate, got %q", got)
	}
	if got := <-clientNames; got != "proxy-client-reloaded" {
		t.Fatalf("expected reloaded client certificate, got %q", got)
	}

	otherCACert, _ := makeCA(t, dir)
	writePEM(t, filepath.Join(dir, "ca.crt"), "CERTIFICATE", otherCACert.Raw)
	transport.CloseIdleConnections()
	if _, err := client.Get(server.URL); err == nil {
		t.Fatal("expected certificate signed by a different CA to be rejected")
	}
}

func tlsConfigForTest(pool *x509.CertPool, cert *x509.Certificate, key *ecdsa.PrivateKey) tls.Config {
	return tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key}}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, MinVersion: tls.VersionTLS12}
}

func makeCA(t *testing.T, dir string) (*x509.Certificate, *ecdsa.PrivateKey) {
	return makeCert(t, "ca", x509.ExtKeyUsageAny, true)
}

func makeLeaf(t *testing.T, dir string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, name string, usage x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey) {
	return makeCertSigned(t, dir, name, ca, caKey, usage)
}

func makeCert(t *testing.T, name string, usage x509.ExtKeyUsage, isCA bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, IsCA: isCA, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	if isCA {
		tmpl.BasicConstraintsValid = true
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

func makeCertSigned(t *testing.T, dir, name string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, usage x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	cert, _ := x509.ParseCertificate(der)
	return cert, key
}

func writePEM(t *testing.T, path, typ string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: data}), 0600); err != nil {
		t.Fatal(err)
	}
}
func clientKeyBytes(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
