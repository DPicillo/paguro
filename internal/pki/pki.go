// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Package pki issues Paguro's own certificates without cert-manager: a
// self-signed CA and one leaf certificate signed by it, kept in a Secret
// (ca.crt, ca.key, tls.crt, tls.key) and renewed before they expire. The
// webhook's serving certificate and the agents' transfer certificate both
// come from here, each with its own CA.
package pki

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"slices"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// Keys in the Secret.
const (
	CACert  = "ca.crt"
	CAKey   = "ca.key"
	TLSCert = corev1.TLSCertKey
	TLSKey  = corev1.TLSPrivateKeyKey
)

const (
	caValidity = 10 * 365 * 24 * time.Hour
	// Certificates expiring within this window are renewed.
	RenewBefore = 60 * 24 * time.Hour
)

// Leaf describes the certificate signed by the CA.
type Leaf struct {
	CommonName string
	DNSNames   []string
	Usages     []x509.ExtKeyUsage
	Validity   time.Duration
}

// SecretKeeper maintains a Secret with a CA and one leaf certificate – or
// only the CA when Leaf.CommonName is empty (a signer's CA, see SignCSR).
type SecretKeeper struct {
	// Client should be uncached when used before the manager starts.
	Client    client.Client
	Namespace string
	Name      string
	// CAName is the CA's common name.
	CAName string
	Leaf   Leaf
	Now    func() time.Time
}

func (k *SecretKeeper) now() time.Time {
	if k.Now != nil {
		return k.Now()
	}
	return time.Now()
}

// Ensure creates or renews the Secret as needed and returns its data.
// Idempotent; safe against concurrent callers (conflicts are re-read).
//
// A renewed leaf keeps the CA, so peers that trust the CA notice nothing.
// A renewed CA keeps the old one in ca.crt as long as it is valid: peers
// that still hold the old leaf (kubelet updates mounted Secrets with a
// delay) stay trusted.
func (k *SecretKeeper) Ensure(ctx context.Context) (map[string][]byte, error) {
	log := logf.FromContext(ctx).WithName("pki")
	key := client.ObjectKey{Namespace: k.Namespace, Name: k.Name}
	for attempt := 0; attempt < 3; attempt++ {
		var sec corev1.Secret
		err := k.Client.Get(ctx, key, &sec)
		if err != nil && !apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("reading secret %s: %w", key, err)
		}
		exists := err == nil
		if exists && k.Valid(sec.Data) {
			return sec.Data, nil
		}

		var caCert, caKey []byte
		reuseCA := exists && k.caValid(sec.Data)
		if reuseCA {
			caCert, caKey = sec.Data[CACert], sec.Data[CAKey]
		} else {
			if caCert, caKey, err = NewCA(k.CAName, k.now()); err != nil {
				return nil, err
			}
			if exists {
				caCert = append(caCert, stillValid(sec.Data[CACert], k.now())...)
			}
		}
		data := map[string][]byte{CACert: caCert, CAKey: caKey}
		if k.Leaf.CommonName != "" {
			certPEM, keyPEM, err := Issue(caCert, caKey, k.Leaf, k.now())
			if err != nil {
				return nil, err
			}
			data[TLSCert], data[TLSKey] = certPEM, keyPEM
		}
		if exists {
			sec.Data = data
			err = k.Client.Update(ctx, &sec)
		} else {
			sec = corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: k.Name, Namespace: k.Namespace,
					Labels: map[string]string{"app.kubernetes.io/managed-by": "paguro"}},
				Type: corev1.SecretTypeOpaque,
				Data: data,
			}
			err = k.Client.Create(ctx, &sec)
		}
		// A concurrently starting replica was faster → re-read.
		if apierrors.IsAlreadyExists(err) || apierrors.IsConflict(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("storing secret %s: %w", key, err)
		}
		log.Info("issued certificate", "secret", key.String(), "commonName", k.Leaf.CommonName, "newCA", !reuseCA)
		return data, nil
	}
	return nil, fmt.Errorf("secret %s: too many concurrent updates", key)
}

func (k *SecretKeeper) caValid(data map[string][]byte) bool {
	cert, err := ParseCert(data[CACert])
	return err == nil && len(data[CAKey]) > 0 && cert.NotAfter.After(k.now().Add(RenewBefore))
}

// Valid reports whether the Secret data needs no renewal.
func (k *SecretKeeper) Valid(data map[string][]byte) bool {
	if !k.caValid(data) {
		return false
	}
	if k.Leaf.CommonName == "" {
		return true
	}
	if len(data[TLSKey]) == 0 {
		return false
	}
	cert, err := ParseCert(data[TLSCert])
	if err != nil || !cert.NotAfter.After(k.now().Add(RenewBefore)) {
		return false
	}
	for _, n := range k.Leaf.DNSNames {
		if !slices.Contains(cert.DNSNames, n) {
			return false
		}
	}
	for _, u := range k.Leaf.Usages {
		if !slices.Contains(cert.ExtKeyUsage, u) {
			return false
		}
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(data[CACert])
	opts := x509.VerifyOptions{Roots: pool, CurrentTime: k.now(), KeyUsages: k.Leaf.Usages}
	if len(k.Leaf.DNSNames) > 0 {
		opts.DNSName = k.Leaf.DNSNames[0]
	}
	_, err = cert.Verify(opts)
	return err == nil
}

// stillValid returns the certificates of a PEM bundle that have not
// expired yet.
func stillValid(bundle []byte, now time.Time) []byte {
	var out []byte
	for rest := bundle; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			return out
		}
		if c, err := x509.ParseCertificate(b.Bytes); err == nil && c.NotAfter.After(now) {
			out = append(out, pem.EncodeToMemory(b)...)
		}
	}
}

// NewCA generates a self-signed CA (ECDSA P-256, ten years).
func NewCA(commonName string, now time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"paguro.dev"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return encode(der, key)
}

// Issue signs a leaf certificate with a new key with the CA (the first
// certificate of caCertPEM).
func Issue(caCertPEM, caKeyPEM []byte, leaf Leaf, now time.Time) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	certPEM, err = Sign(caCertPEM, caKeyPEM, &key.PublicKey, leaf, now)
	if err != nil {
		return nil, nil, err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), nil
}

// Sign certifies pub (from a CSR the caller validated) as leaf. Name,
// usages and lifetime come from leaf, never from the request.
func Sign(caCertPEM, caKeyPEM []byte, pub crypto.PublicKey, leaf Leaf, now time.Time) ([]byte, error) {
	caCert, err := ParseCert(caCertPEM)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(caKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("invalid CA key PEM")
	}
	caKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: leaf.CommonName},
		DNSNames:     leaf.DNSNames,
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(leaf.Validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  leaf.Usages,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pub, caKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// ParseCert parses the first certificate of a PEM bundle.
func ParseCert(p []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(p)
	if block == nil {
		return nil, fmt.Errorf("invalid certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func encode(der []byte, key *ecdsa.PrivateKey) ([]byte, []byte, error) {
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n
}

// Start renews the Secret in time (manager.Runnable, on the leader).
func (k *SecretKeeper) Start(ctx context.Context) error {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if _, err := k.Ensure(ctx); err != nil {
				logf.FromContext(ctx).Error(err, "renewing certificate", "secret", k.Name)
			}
		}
	}
}

// NeedLeaderElection: one replica renews.
func (k *SecretKeeper) NeedLeaderElection() bool { return true }
