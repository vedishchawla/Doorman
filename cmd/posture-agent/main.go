// Command posture-agent generates a signed ES256 posture JWT for use in
// the X-Device-Posture header. On first run it generates a keypair and
// saves it to --key-dir. Prints the signed token to stdout.
package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/vedishchawla/doorman/internal/posture"
)

func main() {
	unhealthy := flag.Bool("unhealthy", false, "emit an unhealthy posture token (for demos)")
	deviceID := flag.String("device-id", hostname(), "device identifier")
	expiry := flag.Duration("expiry", 5*time.Minute, "token expiry duration")
	keyDir := flag.String("key-dir", defaultKeyDir(), "directory to store keypair")
	flag.Parse()

	privKey, pubKeyPEM, err := loadOrGenerateKey(*keyDir)
	if err != nil {
		log.Fatalf("key setup failed: %v", err)
	}

	now := time.Now()
	claims := posture.PostureClaims{
		DeviceID:       *deviceID,
		DiskEncrypted:  true,
		FirewallOn:     true,
		OSPatchAgeDays: 5,
		IssuedAt:       now.Unix(),
		ExpiresAt:      now.Add(*expiry).Unix(),
	}

	if *unhealthy {
		claims.DiskEncrypted = false
		claims.FirewallOn = false
		claims.OSPatchAgeDays = 999
		log.Println("WARNING: emitting unhealthy posture token (demo mode)")
	}

	token, err := posture.SignToken(claims, privKey)
	if err != nil {
		log.Fatalf("failed to sign posture token: %v", err)
	}

	// Print public key PEM to stderr so it can be captured for proxy config
	fmt.Fprintln(os.Stderr, "# Public key (set as POSTURE_PUBLIC_KEY for the proxy):")
	fmt.Fprintln(os.Stderr, pubKeyPEM)

	// Token goes to stdout for piping
	fmt.Println(token)
}

// loadOrGenerateKey loads an existing keypair from keyDir or generates a new one.
func loadOrGenerateKey(keyDir string) (*ecdsa.PrivateKey, string, error) {
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, "", fmt.Errorf("failed to create key dir: %w", err)
	}

	privPath := filepath.Join(keyDir, "posture.key")
	pubPath := filepath.Join(keyDir, "posture.pub")

	// Try to load existing key
	if privData, err := os.ReadFile(privPath); err == nil {
		priv, err := posture.DecodePrivateKeyPEM(string(privData))
		if err != nil {
			return nil, "", fmt.Errorf("failed to decode existing private key: %w", err)
		}
		pubPEM, err := posture.EncodePublicKeyPEM(&priv.PublicKey)
		if err != nil {
			return nil, "", fmt.Errorf("failed to encode public key: %w", err)
		}
		return priv, pubPEM, nil
	}

	// Generate new keypair
	log.Printf("generating new ES256 keypair in %s", keyDir)
	priv, err := posture.GenerateKeyPair()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate keypair: %w", err)
	}

	privPEM, err := posture.EncodePrivateKeyPEM(priv)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encode private key: %w", err)
	}

	pubPEM, err := posture.EncodePublicKeyPEM(&priv.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encode public key: %w", err)
	}

	// Save with restricted permissions
	if err := os.WriteFile(privPath, []byte(privPEM), 0600); err != nil {
		return nil, "", fmt.Errorf("failed to save private key: %w", err)
	}
	if err := os.WriteFile(pubPath, []byte(pubPEM), 0644); err != nil {
		return nil, "", fmt.Errorf("failed to save public key: %w", err)
	}

	log.Printf("saved private key to %s (public key to %s)", privPath, pubPath)
	return priv, pubPEM, nil
}

func defaultKeyDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".zt-posture"
	}
	return filepath.Join(home, ".zt-posture")
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown-device"
	}
	return h
}
