package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// ensureSelfSignedCert loads a cert+key from dir, generating a fresh self-signed
// pair when they're missing or already expired. Returns the loaded certificate.
// The cert covers localhost + all local IPs and is valid for ~10 years; browsers
// will still warn (it's self-signed) but the connection is encrypted.
func ensureSelfSignedCert(dir string) (tls.Certificate, error) {
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		// Reuse only if still valid (parse leaf to check expiry).
		if leaf, perr := x509.ParseCertificate(c.Certificate[0]); perr == nil {
			if time.Now().Before(leaf.NotAfter.Add(-24 * time.Hour)) {
				return c, nil
			}
		}
	}

	if err := generateSelfSigned(certPath, keyPath); err != nil {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
}

// generateSelfSigned writes a new self-signed cert+key (PEM) to the given paths.
func generateSelfSigned(certPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "portknock"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           localIPs(),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}

	certOut, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		certOut.Close()
		return err
	}
	if err := certOut.Close(); err != nil {
		return err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		keyOut.Close()
		return err
	}
	return keyOut.Close()
}

// localIPs returns loopback plus the host's interface IPs, so the cert's SANs
// cover however the admin reaches it. Always includes 127.0.0.1 and ::1.
func localIPs() []net.IP {
	ips := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			ips = append(ips, ipnet.IP)
		}
	}
	return ips
}

// certInfo is a tiny helper for logging what we loaded/generated.
func certInfo(c tls.Certificate) string {
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return "self-signed"
	}
	return fmt.Sprintf("self-signed, valid until %s", leaf.NotAfter.Format("2006-01-02"))
}

