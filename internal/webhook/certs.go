// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package webhook

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"time"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"paguro.dev/paguro/internal/pki"
)

const servingValidity = 2 * 365 * 24 * time.Hour

// CertManager creates and maintains the webhook certificate without cert-manager:
// self-signed CA + serving certificate in a secret (survives restarts),
// files in CertDir for the webhook server, caBundle in the
// MutatingWebhookConfiguration.
type CertManager struct {
	// Client should be uncached (called before the manager starts).
	Client            client.Client
	Namespace         string
	SecretName        string
	ServiceName       string
	WebhookConfigName string
	CertDir           string
	Now               func() time.Time
}

func (c *CertManager) dnsNames() []string {
	return []string{
		c.ServiceName,
		c.ServiceName + "." + c.Namespace,
		c.ServiceName + "." + c.Namespace + ".svc",
		c.ServiceName + "." + c.Namespace + ".svc.cluster.local",
	}
}

func (c *CertManager) keeper() *pki.SecretKeeper {
	return &pki.SecretKeeper{
		Client: c.Client, Namespace: c.Namespace, Name: c.SecretName, CAName: "paguro-webhook-ca", Now: c.Now,
		Leaf: pki.Leaf{CommonName: c.dnsNames()[2], DNSNames: c.dnsNames(),
			Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, Validity: servingValidity},
	}
}

// Ensure ensures the secret, files and caBundle exist. Idempotent.
func (c *CertManager) Ensure(ctx context.Context) error {
	data, err := c.keeper().Ensure(ctx)
	if err != nil {
		return err
	}
	if err := c.writeFiles(data); err != nil {
		return err
	}
	return c.patchCABundle(ctx, data[pki.CACert])
}

// writeFiles writes the serving certificate for the webhook server. The
// server's certificate watcher reloads on every change of the files: an
// unchanged file is left alone, a changed one replaced atomically (written
// in place, the watcher read a truncated key: "failed to find any PEM data").
func (c *CertManager) writeFiles(data map[string][]byte) error {
	if err := os.MkdirAll(c.CertDir, 0o700); err != nil {
		return err
	}
	for _, k := range []string{pki.TLSKey, pki.TLSCert} {
		path := filepath.Join(c.CertDir, k)
		if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, data[k]) {
			continue
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, data[k], 0o600); err != nil {
			return err
		}
		if err := os.Rename(tmp, path); err != nil {
			return err
		}
	}
	return nil
}

func (c *CertManager) patchCABundle(ctx context.Context, ca []byte) error {
	var cfg admissionregistrationv1.MutatingWebhookConfiguration
	if err := c.Client.Get(ctx, client.ObjectKey{Name: c.WebhookConfigName}, &cfg); err != nil {
		if apierrors.IsNotFound(err) {
			// Not created yet (deploy order): Start() catches up later.
			logf.FromContext(ctx).Info("MutatingWebhookConfiguration not found yet, will retry", "name", c.WebhookConfigName)
			return nil
		}
		return fmt.Errorf("reading MutatingWebhookConfiguration %s: %w", c.WebhookConfigName, err)
	}
	base := cfg.DeepCopy()
	changed := false
	for i := range cfg.Webhooks {
		if !bytes.Equal(cfg.Webhooks[i].ClientConfig.CABundle, ca) {
			cfg.Webhooks[i].ClientConfig.CABundle = ca
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err := c.Client.Patch(ctx, &cfg, client.MergeFrom(base)); err != nil {
		return fmt.Errorf("patching caBundle of %s: %w", c.WebhookConfigName, err)
	}
	logf.FromContext(ctx).Info("patched webhook caBundle", "config", c.WebhookConfigName)
	return nil
}

// Start keeps the caBundle and certificate up to date (e.g. when someone
// re-applied the webhook configuration and thereby cleared the caBundle).
// Implements manager.Runnable; runs on every replica.
func (c *CertManager) Start(ctx context.Context) error {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := c.Ensure(ctx); err != nil {
				logf.FromContext(ctx).Error(err, "refreshing webhook certificate")
			}
		}
	}
}

// NeedLeaderElection: every replica serves webhook requests.
func (c *CertManager) NeedLeaderElection() bool { return false }
