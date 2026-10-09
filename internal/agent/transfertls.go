// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	certv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/agentca"
)

// TransferTLS is this agent's side of the mutual TLS between agents: a
// certificate for its own node (internal/agentca) and the agents' CA. The
// key never leaves the process; the certificate is requested at start and
// renewed after two thirds of its lifetime. The CA bundle is a mounted
// ConfigMap, read again on every handshake (kubelet updates it when the CA
// is renewed).
type TransferTLS struct {
	CAFile string
	Node   string
	// Request sends a PEM certificate request and returns the PEM
	// certificate (CertificateRequester).
	Request func(ctx context.Context, csrPEM []byte) ([]byte, error)
	Now     func() time.Time

	mu    sync.Mutex
	cert  *tls.Certificate
	caRaw []byte
	pool  *x509.CertPool
}

var errNoCertificate = errors.New("no transfer certificate yet")

func (t *TransferTLS) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

// trust returns the CA pool; a failed read keeps the last good bundle.
func (t *TransferTLS) trust() (*x509.CertPool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	raw, err := os.ReadFile(t.CAFile)
	if err != nil {
		if t.pool != nil {
			return t.pool, nil
		}
		return nil, fmt.Errorf("agents' CA: %w", err)
	}
	if t.pool == nil || !bytes.Equal(raw, t.caRaw) {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			if t.pool != nil {
				return t.pool, nil
			}
			return nil, fmt.Errorf("agents' CA: no certificate in %s", t.CAFile)
		}
		t.caRaw, t.pool = raw, pool
	}
	return t.pool, nil
}

func (t *TransferTLS) certificate() (*tls.Certificate, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cert == nil {
		return nil, errNoCertificate
	}
	return t.cert, nil
}

// obtain requests a certificate for a new key.
func (t *TransferTLS) obtain(ctx context.Context) error {
	pool, err := t.trust()
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: t.Node}, DNSNames: []string{t.Node},
	}, key)
	if err != nil {
		return err
	}
	certPEM, err := t.Request(ctx, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	if err != nil {
		return err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
	if err != nil {
		return fmt.Errorf("issued certificate: %w", err)
	}
	if cert.Leaf.Subject.CommonName != t.Node {
		return fmt.Errorf("issued certificate names %q, not this node", cert.Leaf.Subject.CommonName)
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: t.now(), DNSName: t.Node,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("issued certificate: %w", err)
	}
	t.mu.Lock()
	t.cert = &cert
	t.mu.Unlock()
	certExpiry.Set(float64(cert.Leaf.NotAfter.Unix()))
	return nil
}

// renewAt is when the current certificate is due: after two thirds of its
// lifetime (at once when there is none).
func (t *TransferTLS) renewAt() time.Time {
	c, err := t.certificate()
	if err != nil {
		return time.Time{}
	}
	nb, na := c.Leaf.NotBefore, c.Leaf.NotAfter
	return nb.Add(na.Sub(nb) * 2 / 3)
}

// Run obtains the certificate and renews it until ctx ends; failures are
// retried with backoff (the controller may not run yet).
func (t *TransferTLS) Run(ctx context.Context, log *slog.Logger) {
	backoff := 2 * time.Second
	for {
		wait := time.Minute
		if !t.now().Before(t.renewAt()) {
			if err := t.obtain(ctx); err != nil {
				log.Warn("transfer certificate", "err", err, "retryIn", backoff.String())
				wait, backoff = backoff, min(backoff*2, time.Minute)
			} else {
				c, _ := t.certificate()
				log.Info("transfer certificate issued", "node", t.Node, "notAfter", c.Leaf.NotAfter)
				backoff = 2 * time.Second
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// Wait blocks until certificate and CA are there.
func (t *TransferTLS) Wait(ctx context.Context, log *slog.Logger) error {
	next := time.Now()
	for {
		_, err := t.certificate()
		if err == nil {
			_, err = t.trust()
		}
		if err == nil {
			return nil
		}
		if time.Now().After(next) {
			log.Info("waiting for the transfer certificate", "err", err)
			next = time.Now().Add(30 * time.Second)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// ServerConfig requires a client certificate from the agents' CA; which
// node may send what is decided per request (Agent.AuthorizeTransfer).
func (t *TransferTLS) ServerConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			cert, err := t.certificate()
			if err != nil {
				return nil, err
			}
			pool, err := t.trust()
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: []tls.Certificate{*cert},
				ClientCAs:    pool,
				ClientAuth:   tls.RequireAndVerifyClientCert,
			}, nil
		},
	}
}

// ClientConfig trusts only the certificate of serverNode from the agents'
// CA and presents this node's.
func (t *TransferTLS) ClientConfig(serverNode string) (*tls.Config, error) {
	if _, err := t.certificate(); err != nil {
		return nil, err
	}
	pool, err := t.trust()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return t.certificate()
		},
		RootCAs:    pool,
		ServerName: serverNode,
	}, nil
}

// PeerNode is the node a verified client certificate names ("" without).
func PeerNode(cs *tls.ConnectionState) string {
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 {
		return ""
	}
	return cs.PeerCertificates[0].Subject.CommonName
}

// CertificateRequester returns TransferTLS.Request for node: one
// CertificateSigningRequest per call, waited for until the controller signed
// or denied it.
func CertificateRequester(cs kubernetes.Interface, node string) func(context.Context, []byte) ([]byte, error) {
	return func(ctx context.Context, csrPEM []byte) ([]byte, error) {
		exp := int32(agentca.MaxValidity / time.Second)
		prefix := "paguro-agent-" + node
		if len(prefix) > 200 {
			prefix = prefix[:200]
		}
		created, err := cs.CertificatesV1().CertificateSigningRequests().Create(ctx, &certv1.CertificateSigningRequest{
			ObjectMeta: metav1.ObjectMeta{GenerateName: prefix + "-"},
			Spec: certv1.CertificateSigningRequestSpec{
				Request: csrPEM, SignerName: agentca.SignerName, ExpirationSeconds: &exp,
				Usages: []certv1.KeyUsage{certv1.UsageDigitalSignature, certv1.UsageServerAuth, certv1.UsageClientAuth},
			},
		}, metav1.CreateOptions{})
		if err != nil {
			return nil, fmt.Errorf("creating the certificate request: %w", err)
		}
		ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		for {
			cur, err := cs.CertificatesV1().CertificateSigningRequests().Get(ctx, created.Name, metav1.GetOptions{})
			if err == nil {
				if len(cur.Status.Certificate) > 0 {
					return cur.Status.Certificate, nil
				}
				for _, c := range cur.Status.Conditions {
					if (c.Type == certv1.CertificateDenied || c.Type == certv1.CertificateFailed) && c.Status == "True" {
						return nil, fmt.Errorf("certificate request %s %s: %s", created.Name, c.Type, c.Message)
					}
				}
			}
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("certificate request %s not signed (is the controller running?): %w", created.Name, ctx.Err())
			case <-time.After(500 * time.Millisecond):
			}
		}
	}
}

// MarkTransferUp is called once the transfer server listens.
func (a *Agent) MarkTransferUp() { a.transferUp.Store(true) }

// transferEndpoint is the address other agents send to: "https://ip:port"
// with TLS, plain "ip:port" without.
func (a *Agent) transferEndpoint() string {
	if a.TransferTLS != nil {
		return "https://" + a.Endpoint
	}
	return a.Endpoint
}

// advertisedEndpoint is the node annotation: empty until the server
// listens, so that no migration picks this node too early.
func (a *Agent) advertisedEndpoint() string {
	if !a.transferUp.Load() {
		return ""
	}
	return a.transferEndpoint()
}

// newClient sends to the agent of targetNode at endpoint. Transfer TLS is
// all or nothing: an agent with a certificate never sends memory images in
// plain text, and one without cannot reach a TLS endpoint.
func (a *Agent) newClient(endpoint, targetNode string) (*Client, error) {
	return NewClient(endpoint, a.Token, a.TransferTLS, targetNode)
}

// AuthorizeTransfer admits a request for migration uid only from the
// migration's source node and only on its target node (with transfer TLS;
// the shared token alone cannot tell nodes apart).
func (a *Agent) AuthorizeTransfer(r *http.Request, uid string) error {
	if a.TransferTLS == nil {
		return nil
	}
	src, dst, err := a.migrationNodes(r.Context(), types.UID(uid))
	if err != nil {
		return err
	}
	if dst != a.NodeName {
		return fmt.Errorf("this node is not the target of migration %s", uid)
	}
	if peer := PeerNode(r.TLS); peer == "" || peer != src {
		return fmt.Errorf("node %q is not the source of migration %s", peer, uid)
	}
	return nil
}

// migrationNodes returns source and target node of a migration, from the
// cache or – just created – the API server. Neither changes once set.
func (a *Agent) migrationNodes(ctx context.Context, uid types.UID) (string, string, error) {
	a.peerMu.Lock()
	n, ok := a.peers[uid]
	a.peerMu.Unlock()
	if ok {
		return n[0], n[1], nil
	}
	find := func(list *v1.MigrationList) *v1.Migration {
		for i := range list.Items {
			if list.Items[i].UID == uid {
				return &list.Items[i]
			}
		}
		return nil
	}
	var m *v1.Migration
	if list := (&v1.MigrationList{}); a.Client.List(ctx, list) == nil {
		m = find(list)
	}
	if m == nil {
		list := &v1.MigrationList{}
		if err := a.APIReader.List(ctx, list); err != nil {
			return "", "", err
		}
		if m = find(list); m == nil {
			return "", "", fmt.Errorf("no migration %s", uid)
		}
	}
	src, dst := m.Status.SourceNode, m.Status.TargetNode
	if src != "" && dst != "" {
		a.peerMu.Lock()
		if a.peers == nil || len(a.peers) > 1024 {
			a.peers = map[types.UID][2]string{}
		}
		a.peers[uid] = [2]string{src, dst}
		a.peerMu.Unlock()
	}
	return src, dst, nil
}
