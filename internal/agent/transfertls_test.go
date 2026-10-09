// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	certv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1 "paguro.dev/paguro/api/v1alpha1"
	"paguro.dev/paguro/internal/agentca"
	"paguro.dev/paguro/internal/pki"
)

type testCA struct{ cert, key []byte }

func newTestCA(t testing.TB) testCA {
	t.Helper()
	c, k, err := pki.NewCA("test-ca", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return testCA{c, k}
}

// sign is a stand-in for the controller: it certifies the requested name.
func (ca testCA) sign(validity time.Duration) func(context.Context, []byte) ([]byte, error) {
	return func(_ context.Context, csrPEM []byte) ([]byte, error) {
		b, _ := pem.Decode(csrPEM)
		req, err := x509.ParseCertificateRequest(b.Bytes)
		if err != nil {
			return nil, err
		}
		return pki.Sign(ca.cert, ca.key, req.PublicKey, agentca.Leaf(req.Subject.CommonName, validity), time.Now())
	}
}

// nodeTLS returns a node's TransferTLS with its certificate from ca.
func (ca testCA) nodeTLS(t testing.TB, node string) *TransferTLS {
	t.Helper()
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caFile, ca.cert, 0o600); err != nil {
		t.Fatal(err)
	}
	tt := &TransferTLS{CAFile: caFile, Node: node, Request: ca.sign(time.Hour)}
	if err := tt.obtain(context.Background()); err != nil {
		t.Fatal(err)
	}
	return tt
}

// serveTLS starts a transfer-like server that answers 204 and records the
// client's node; returns "https://host:port".
func serveTLS(t testing.TB, tt *TransferTLS, peer *string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if peer != nil {
			*peer = PeerNode(r.TLS)
		}
		w.WriteHeader(http.StatusNoContent)
	})}
	go func() { _ = srv.Serve(tls.NewListener(ln, tt.ServerConfig())) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "https://" + ln.Addr().String()
}

// Each side proves its node: the client checks the server is the target
// node, the server learns the client's node.
func TestTransferMutualTLS(t *testing.T) {
	ca := newTestCA(t)
	var peer string
	endpoint := serveTLS(t, ca.nodeTLS(t, "n2"), &peer)

	c, err := NewClient(endpoint, "t", ca.nodeTLS(t, "n1"), "n2")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.HandOver(context.Background(), "mig-uid"); err != nil {
		t.Fatalf("hand-over over mTLS: %v", err)
	}
	if peer != "n1" {
		t.Fatalf("server saw peer %q", peer)
	}

	// The same server is not node n3.
	c, _ = NewClient(endpoint, "t", ca.nodeTLS(t, "n1"), "n3")
	if err := c.HandOver(context.Background(), "mig-uid"); err == nil || !strings.Contains(err.Error(), "n3") {
		t.Fatalf("want a name mismatch, got %v", err)
	}
}

// Neither a certificate from another CA nor none gets through.
func TestTransferTLSRejectsStrangers(t *testing.T) {
	ca, other := newTestCA(t), newTestCA(t)
	endpoint := serveTLS(t, ca.nodeTLS(t, "n2"), nil)

	stranger := other.nodeTLS(t, "n1")
	stranger.CAFile = ca.nodeTLS(t, "x").CAFile // trusts the server, holds a foreign certificate
	c, err := NewClient(endpoint, "t", stranger, "n2")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.HandOver(context.Background(), "mig-uid"); err == nil {
		t.Fatal("a certificate of another CA must be rejected")
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.cert)
	noCert := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "n2"}}}
	if resp, err := noCert.Post(endpoint+"/v1/m/x/handover", "", nil); err == nil {
		resp.Body.Close()
		t.Fatal("a client without certificate must be rejected")
	}
}

// TLS is all or nothing: no plain-text send from an agent with a
// certificate, no TLS endpoint for one without.
func TestTransferTLSSchemeMismatch(t *testing.T) {
	tt := newTestCA(t).nodeTLS(t, "n1")
	if _, err := NewClient("10.0.0.2:9555", "t", tt, "n2"); err == nil {
		t.Fatal("plain endpoint accepted by an agent with transfer TLS")
	}
	if _, err := NewClient("https://10.0.0.2:9555", "t", nil, "n2"); err == nil {
		t.Fatal("TLS endpoint accepted by an agent without certificate")
	}
	if c, err := NewClient("10.0.0.2:9555", "t", nil, ""); err != nil || c.url("/x") != "http://10.0.0.2:9555/x" {
		t.Fatalf("plain endpoint: %v", err)
	}
}

// A target takes a migration's data only from its source node, and only
// if it is the target itself.
func TestAuthorizeTransfer(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = v1.AddToScheme(scheme)
	mig := &v1.Migration{ObjectMeta: metav1.ObjectMeta{Name: "m", Namespace: "ns", UID: "mig-uid"},
		Status: v1.MigrationStatus{SourceNode: "n1", TargetNode: "n2"}}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(mig).Build()
	ca := newTestCA(t)
	certOf := func(node string) *tls.ConnectionState {
		c, _ := ca.nodeTLS(t, node).certificate()
		return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{c.Leaf}, VerifiedChains: [][]*x509.Certificate{{c.Leaf}}}
	}
	req := func(peer *tls.ConnectionState) *http.Request {
		r := httptest.NewRequest(http.MethodPut, "/v1/m/mig-uid/meta", nil)
		r.TLS = peer
		return r
	}
	target := &Agent{Client: cl, APIReader: cl, NodeName: "n2", TransferTLS: &TransferTLS{}}
	if err := target.AuthorizeTransfer(req(certOf("n1")), "mig-uid"); err != nil {
		t.Fatalf("source to target: %v", err)
	}
	if err := target.AuthorizeTransfer(req(certOf("n3")), "mig-uid"); err == nil {
		t.Fatal("a bystander node may not send")
	}
	if err := target.AuthorizeTransfer(req(nil), "mig-uid"); err == nil {
		t.Fatal("no certificate, no data")
	}
	if err := target.AuthorizeTransfer(req(certOf("n1")), "other-uid"); err == nil {
		t.Fatal("unknown migration accepted")
	}
	bystander := &Agent{Client: cl, APIReader: cl, NodeName: "n3", TransferTLS: &TransferTLS{}}
	if err := bystander.AuthorizeTransfer(req(certOf("n1")), "mig-uid"); err == nil {
		t.Fatal("a node that is not the target accepted data")
	}
	if err := (&Agent{NodeName: "n3"}).AuthorizeTransfer(req(nil), "mig-uid"); err != nil {
		t.Fatal("without transfer TLS the token decides")
	}
}

// The certificate is renewed after two thirds of its lifetime; handshakes
// use the new one at once. A renewed CA bundle is read on the next one.
func TestTransferTLSRenewal(t *testing.T) {
	ca := newTestCA(t)
	tt := ca.nodeTLS(t, "n2")
	first, _ := tt.certificate()
	now := time.Now()
	tt.Now = func() time.Time { return now }
	if !now.Before(tt.renewAt()) {
		t.Fatal("fresh certificate due already")
	}
	now = first.Leaf.NotBefore.Add(first.Leaf.NotAfter.Sub(first.Leaf.NotBefore) * 2 / 3).Add(time.Second)
	if now.Before(tt.renewAt()) {
		t.Fatal("certificate not due after two thirds")
	}
	tt.Now = nil
	endpoint := strings.TrimPrefix(serveTLS(t, tt, nil), "https://")
	served := func() *x509.Certificate {
		cfg, err := ca.nodeTLS(t, "n1").ClientConfig("n2")
		if err != nil {
			t.Fatal(err)
		}
		conn, err := tls.Dial("tcp", endpoint, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0]
	}
	if served().SerialNumber.Cmp(first.Leaf.SerialNumber) != 0 {
		t.Fatal("first certificate not served")
	}
	if err := tt.obtain(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, _ := tt.certificate()
	if served().SerialNumber.Cmp(second.Leaf.SerialNumber) != 0 {
		t.Fatal("renewed certificate not served")
	}

	// New CA first in the bundle, old one kept: certificates of both verify.
	next := newTestCA(t)
	_ = os.WriteFile(tt.CAFile, append(append([]byte{}, next.cert...), ca.cert...), 0o600)
	tt.Request = next.sign(time.Hour)
	if err := tt.obtain(context.Background()); err != nil {
		t.Fatalf("certificate from the new CA: %v", err)
	}
	// A broken bundle keeps the last good one.
	_ = os.WriteFile(tt.CAFile, []byte("garbage"), 0o600)
	if _, err := tt.trust(); err != nil {
		t.Fatal(err)
	}
}

// A denied or failing request leaves the agent without certificate – it
// keeps trying (Run) and accepts no migrations meanwhile (Wait).
func TestTransferTLSWait(t *testing.T) {
	ca := newTestCA(t)
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	_ = os.WriteFile(caFile, ca.cert, 0o600)
	calls := 0
	tt := &TransferTLS{CAFile: caFile, Node: "n1", Request: func(ctx context.Context, b []byte) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("denied")
		}
		return ca.sign(time.Hour)(ctx, b)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := tt.Wait(ctx, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("Wait returned without certificate")
	}
	if _, err := tt.ClientConfig("n2"); err == nil {
		t.Fatal("client config without certificate")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go tt.Run(ctx, slog.New(slog.DiscardHandler))
	if err := tt.Wait(ctx, slog.New(slog.DiscardHandler)); err != nil || calls != 2 {
		t.Fatalf("Run did not retry: %v, %d calls", err, calls)
	}
}

// One CertificateSigningRequest per call, for the agents' signer, waited
// for until signed or denied.
func TestCertificateRequester(t *testing.T) {
	cs := k8sfake.NewClientset()
	// The fake API server does not generate names.
	n := 0
	cs.PrependReactor("create", "certificatesigningrequests", func(a k8stesting.Action) (bool, runtime.Object, error) {
		c := a.(k8stesting.CreateAction).GetObject().(*certv1.CertificateSigningRequest)
		n++
		c.Name = c.GenerateName + string(rune('a'+n))
		return false, nil, nil
	})
	csrs := cs.CertificatesV1().CertificateSigningRequests()
	decide := func(update func(*certv1.CertificateSigningRequest)) {
		for range 200 {
			l, _ := csrs.List(context.Background(), metav1.ListOptions{})
			for i := range l.Items {
				c := &l.Items[i]
				if len(c.Status.Conditions) == 0 && len(c.Status.Certificate) == 0 {
					if c.Spec.SignerName != agentca.SignerName || !strings.HasPrefix(c.Name, "paguro-agent-n1-") {
						t.Errorf("request %s %+v", c.Name, c.Spec)
					}
					update(c)
					_, _ = csrs.UpdateStatus(context.Background(), c, metav1.UpdateOptions{})
					return
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	req := CertificateRequester(cs, "n1")
	go decide(func(c *certv1.CertificateSigningRequest) { c.Status.Certificate = []byte("CERT") })
	if got, err := req(context.Background(), []byte("CSR")); err != nil || string(got) != "CERT" {
		t.Fatalf("signed: %q %v", got, err)
	}
	go decide(func(c *certv1.CertificateSigningRequest) {
		c.Status.Conditions = []certv1.CertificateSigningRequestCondition{{Type: certv1.CertificateDenied, Status: "True", Message: "no"}}
	})
	if _, err := req(context.Background(), []byte("CSR")); err == nil || !strings.Contains(err.Error(), "Denied") {
		t.Fatalf("denied: %v", err)
	}
}

// The node advertises its endpoint only once the server listens, with the
// scheme the transfer uses.
func TestAdvertisedEndpoint(t *testing.T) {
	a := &Agent{Endpoint: "10.0.0.1:9555"}
	if a.advertisedEndpoint() != "" {
		t.Fatal("endpoint advertised before the server listens")
	}
	a.MarkTransferUp()
	if a.advertisedEndpoint() != "10.0.0.1:9555" {
		t.Fatal(a.advertisedEndpoint())
	}
	a.TransferTLS = &TransferTLS{}
	if a.advertisedEndpoint() != "https://10.0.0.1:9555" || a.transferEndpoint() != "https://10.0.0.1:9555" {
		t.Fatal(a.advertisedEndpoint())
	}
}
