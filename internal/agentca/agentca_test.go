// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

package agentca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"paguro.dev/paguro/internal/pki"
)

const agentUser = "system:serviceaccount:paguro-system:paguro-agent"

func request(t *testing.T, key crypto.Signer, tmpl *x509.CertificateRequest) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func csrFor(user, tokenNode string, req []byte, usages ...certv1.KeyUsage) *certv1.CertificateSigningRequest {
	if usages == nil {
		usages = []certv1.KeyUsage{certv1.UsageDigitalSignature, certv1.UsageServerAuth, certv1.UsageClientAuth}
	}
	c := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "paguro-agent-n1-abc"},
		Spec: certv1.CertificateSigningRequestSpec{
			Request: req, SignerName: SignerName, Usages: usages, Username: user,
		},
	}
	if tokenNode != "" {
		c.Spec.Extra = map[string]certv1.ExtraValue{NodeNameExtra: {tokenNode}}
	}
	return c
}

func TestValidate(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	good := request(t, ec, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "n1"}, DNSNames: []string{"n1"}})

	if node, _, err := Validate(csrFor(agentUser, "n1", good), agentUser, nil); err != nil || node != "n1" {
		t.Fatalf("valid request: %v %v", node, err)
	}
	for name, c := range map[string]*certv1.CertificateSigningRequest{
		"another user":    csrFor("system:serviceaccount:default:x", "n1", good),
		"token not bound": csrFor(agentUser, "", good),
		"another node":    csrFor(agentUser, "n2", good),
		"extra DNS name":  csrFor(agentUser, "n1", request(t, ec, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "n1"}, DNSNames: []string{"n1", "kubernetes"}})),
		"IP address":      csrFor(agentUser, "n1", request(t, ec, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "n1"}, IPAddresses: []net.IP{net.ParseIP("10.0.0.1")}})),
		"RSA key":         csrFor(agentUser, "n1", request(t, rk, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "n1"}})),
		"code signing":    csrFor(agentUser, "n1", good, certv1.UsageCodeSigning),
		"no PEM":          csrFor(agentUser, "n1", []byte("garbage")),
		"common name n2":  csrFor(agentUser, "n1", request(t, ec, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "n2"}})),
	} {
		if _, _, err := Validate(c, agentUser, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Before Kubernetes 1.30 a token names its pod, not its node: the node is
// the pod's, and only while the pod (same UID) exists.
func TestValidatePodToken(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	req := request(t, ec, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "n1"}})
	c := csrFor(agentUser, "", req)
	c.Spec.Extra = map[string]certv1.ExtraValue{podNameExtra: {"paguro-agent-abc"}, podUIDExtra: {"uid-1"}}
	pods := func(name, uid string) (string, error) {
		if name == "paguro-agent-abc" && uid == "uid-1" {
			return "n1", nil
		}
		return "", errors.New("gone")
	}
	if node, _, err := Validate(c, agentUser, pods); err != nil || node != "n1" {
		t.Fatalf("pod token: %v %v", node, err)
	}
	c.Spec.Extra[podUIDExtra] = certv1.ExtraValue{"uid-2"}
	if _, _, err := Validate(c, agentUser, pods); err == nil {
		t.Fatal("a token of a pod that is gone accepted")
	}
	c.Spec.Extra = map[string]certv1.ExtraValue{podNameExtra: {"paguro-agent-abc"}, podUIDExtra: {"uid-1"}}
	other := func(string, string) (string, error) { return "n2", nil }
	if _, _, err := Validate(c, agentUser, other); err == nil {
		t.Fatal("a certificate for another node than the pod's accepted")
	}
}

// Reconcile approves and signs a valid request – the certificate names the
// node from the token, whatever else the request said – and denies others.
func TestReconcile(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	good := csrFor(agentUser, "n1", request(t, ec, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "n1"}}))
	bad := csrFor(agentUser, "n2", good.Spec.Request)
	bad.Name = "paguro-agent-n2-xyz"

	updates := map[string][]string{}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(good, bad).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
				updates[obj.GetName()] = append(updates[obj.GetName()], sub)
				// Approval and certificate both live in the status.
				return c.SubResource("status").Update(ctx, obj)
			},
		}).Build()
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	s := &Signer{Client: cl, AgentUser: agentUser, Now: func() time.Time { return now },
		CA:     &pki.SecretKeeper{Client: cl, Namespace: "paguro-system", Name: "paguro-agent-ca", CAName: "paguro-agent-ca", Now: func() time.Time { return now }},
		Bundle: types.NamespacedName{Namespace: "paguro-system", Name: "paguro-agent-ca"}}
	if err := s.Publish(context.Background()); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{good.Name, bad.Name} {
		if _, err := s.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}); err != nil {
			t.Fatal(err)
		}
	}
	got := &certv1.CertificateSigningRequest{}
	_ = cl.Get(context.Background(), client.ObjectKey{Name: good.Name}, got)
	if strings.Join(updates[good.Name], ",") != "approval,status" || len(got.Status.Certificate) == 0 {
		t.Fatalf("good: updates %v, certificate %d bytes", updates[good.Name], len(got.Status.Certificate))
	}
	cert, err := pki.ParseCert(got.Status.Certificate)
	if err != nil || cert.Subject.CommonName != "n1" || len(cert.DNSNames) != 1 || cert.DNSNames[0] != "n1" ||
		cert.NotAfter.Sub(now) > MaxValidity+time.Minute {
		t.Fatalf("certificate: %v %v %v", err, cert.Subject, cert.NotAfter)
	}
	cm := &corev1.ConfigMap{}
	_ = cl.Get(context.Background(), s.Bundle, cm)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(cm.Data[CAFile]))
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now, DNSName: "n1",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("certificate does not chain to the published CA: %v", err)
	}

	_ = cl.Get(context.Background(), client.ObjectKey{Name: bad.Name}, got)
	if strings.Join(updates[bad.Name], ",") != "approval" || len(got.Status.Certificate) != 0 ||
		!condition(got, certv1.CertificateDenied) {
		t.Fatalf("bad: updates %v, conditions %v", updates[bad.Name], got.Status.Conditions)
	}

	// Decided requests are left alone.
	if _, err := s.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: bad.Name}}); err != nil ||
		len(updates[bad.Name]) != 1 {
		t.Fatal("a denied request was handled again")
	}
}

func TestValidity(t *testing.T) {
	c := &certv1.CertificateSigningRequest{}
	if validity(c) != MaxValidity {
		t.Fatal("default")
	}
	short, long := int32(60), int32(30*24*3600)
	c.Spec.ExpirationSeconds = &short
	if validity(c) != time.Hour {
		t.Fatal("minimum")
	}
	c.Spec.ExpirationSeconds = &long
	if validity(c) != MaxValidity {
		t.Fatal("maximum")
	}
}
