// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package pki

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func countCerts(bundle []byte) int {
	n := 0
	for rest := bundle; ; n++ {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			return n
		}
	}
}

func TestSecretKeeperLifecycle(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	k := &SecretKeeper{Client: c, Namespace: "paguro-system", Name: "paguro-agent-tls", CAName: "paguro-agent-ca",
		Now: func() time.Time { return now },
		Leaf: Leaf{CommonName: "paguro-agent", DNSNames: []string{"paguro-agent"},
			Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, Validity: 365 * 24 * time.Hour}}
	ctx := context.Background()
	get := func() map[string][]byte {
		var s corev1.Secret
		if err := c.Get(ctx, types.NamespacedName{Namespace: "paguro-system", Name: "paguro-agent-tls"}, &s); err != nil {
			t.Fatal(err)
		}
		return s.Data
	}

	first, err := k.Ensure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !k.Valid(get()) {
		t.Fatal("issued certificate does not validate")
	}
	leaf, _ := ParseCert(first[TLSCert])
	if len(leaf.ExtKeyUsage) != 2 || leaf.IsCA {
		t.Fatalf("leaf usages %v", leaf.ExtKeyUsage)
	}

	// Restart: nothing changes.
	if _, err := k.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(get()[TLSCert], first[TLSCert]) {
		t.Fatal("valid certificate must be kept")
	}

	// Leaf near expiry: new leaf, same CA bundle.
	now = now.Add(365*24*time.Hour - 30*24*time.Hour)
	if _, err := k.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	second := get()
	if bytes.Equal(second[TLSCert], first[TLSCert]) || !bytes.Equal(second[CACert], first[CACert]) {
		t.Fatal("want a renewed leaf under the same CA")
	}

	// CA near expiry: new CA first in the bundle, the old one still
	// trusted until it expires.
	now = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).Add(caValidity - 30*24*time.Hour)
	if _, err := k.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	third := get()
	if countCerts(third[CACert]) != 2 || !bytes.Contains(third[CACert], first[CACert]) {
		t.Fatalf("want new CA plus the old one, got %d certificates", countCerts(third[CACert]))
	}
	if !k.Valid(third) {
		t.Fatal("renewed CA does not validate")
	}

	// Once the old CA expired, the next renewal drops it.
	now = now.Add(caValidity - 30*24*time.Hour)
	if _, err := k.Ensure(ctx); err != nil {
		t.Fatal(err)
	}
	if n := countCerts(get()[CACert]); n != 2 {
		t.Fatalf("want the second CA plus the third, got %d certificates", n)
	}
	if bytes.Contains(get()[CACert], first[CACert]) {
		t.Fatal("expired CA kept in the bundle")
	}
}

// A leaf lacking a required usage (e.g. a serving-only certificate where
// the agents need client auth too) is replaced.
func TestValidRequiresUsages(t *testing.T) {
	now := time.Now()
	caCert, caKey, err := NewCA("ca", now)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := Issue(caCert, caKey, Leaf{CommonName: "a", DNSNames: []string{"a"},
		Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, Validity: time.Hour * 24 * 365}, now)
	if err != nil {
		t.Fatal(err)
	}
	k := &SecretKeeper{Leaf: Leaf{CommonName: "a", DNSNames: []string{"a"},
		Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}}
	if k.Valid(map[string][]byte{CACert: caCert, CAKey: caKey, TLSCert: cert, TLSKey: key}) {
		t.Fatal("certificate without client auth accepted")
	}
}
