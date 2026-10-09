// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 David Picillo

// Package agentca gives every agent a certificate for its own node, used for
// the mutual TLS of the transfer between agents. The agent generates its key
// and asks through the certificates.k8s.io API (signer paguro.dev/agent);
// the controller signs only a request whose service account token was bound
// to a pod on the node the certificate names. A target then takes data only
// from the migration's source node and a source sends only to its target
// node: a compromised node can neither feed forged memory images into other
// nodes' migrations nor pose as their target.
//
// The CA lives in a Secret only the controller reads; agents get its
// certificate from a ConfigMap.
package agentca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"paguro.dev/paguro/internal/pki"
)

// SignerName is the signer of the agents' certificates.
const SignerName = "paguro.dev/agent"

// NodeNameExtra is the user info a pod-bound service account token
// carries (Kubernetes >= 1.30): the node of the pod it was issued for.
const NodeNameExtra = "authentication.kubernetes.io/node-name"

// Before 1.30 a pod-bound token names only its pod; the pod's node is then
// looked up (the pod's UID must match, so a token outlives no pod).
const (
	podNameExtra = "authentication.kubernetes.io/pod-name"
	podUIDExtra  = "authentication.kubernetes.io/pod-uid"
)

// CAFile is the key in the ConfigMap with the CA bundle.
const CAFile = "ca.crt"

const (
	// MaxValidity: agents renew after two thirds of it.
	MaxValidity = 7 * 24 * time.Hour
	minValidity = time.Hour
)

var allowedUsages = []certv1.KeyUsage{
	certv1.UsageDigitalSignature, certv1.UsageKeyEncipherment, certv1.UsageServerAuth, certv1.UsageClientAuth,
}

// Signer approves and signs the agents' requests (leader only) and keeps the
// CA bundle published.
type Signer struct {
	Client client.Client
	// CA: a SecretKeeper without leaf.
	CA *pki.SecretKeeper
	// AgentUser is the agents' service account user name.
	AgentUser string
	// Bundle is the ConfigMap the agents mount.
	Bundle types.NamespacedName
	Now    func() time.Time
}

func (s *Signer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Signer) SetupWithManager(mgr ctrl.Manager) error {
	ours := predicate.NewPredicateFuncs(func(o client.Object) bool {
		csr, ok := o.(*certv1.CertificateSigningRequest)
		return ok && csr.Spec.SignerName == SignerName
	})
	return ctrl.NewControllerManagedBy(mgr).Named("agent-certificates").
		For(&certv1.CertificateSigningRequest{}, builder.WithPredicates(ours)).Complete(s)
}

// Reconcile decides one request: denied with the reason, or approved and
// signed.
func (s *Signer) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	csr := &certv1.CertificateSigningRequest{}
	if err := s.Client.Get(ctx, req.NamespacedName, csr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if csr.Spec.SignerName != SignerName || len(csr.Status.Certificate) > 0 ||
		condition(csr, certv1.CertificateDenied) || condition(csr, certv1.CertificateFailed) {
		return ctrl.Result{}, nil
	}
	log := logf.FromContext(ctx).WithValues("csr", csr.Name)
	node, pub, err := Validate(csr, s.AgentUser, s.podNode(ctx))
	if err != nil {
		log.Info("denied an agent certificate request", "reason", err.Error())
		csr.Status.Conditions = append(csr.Status.Conditions, certv1.CertificateSigningRequestCondition{
			Type: certv1.CertificateDenied, Status: corev1.ConditionTrue, Reason: "PaguroAgentPolicy",
			Message: err.Error(), LastUpdateTime: metav1.Now(),
		})
		return ctrl.Result{}, s.Client.SubResource("approval").Update(ctx, csr)
	}
	if !condition(csr, certv1.CertificateApproved) {
		csr.Status.Conditions = append(csr.Status.Conditions, certv1.CertificateSigningRequestCondition{
			Type: certv1.CertificateApproved, Status: corev1.ConditionTrue, Reason: "PaguroAgentNode",
			Message: "the requester's token is bound to a pod on node " + node, LastUpdateTime: metav1.Now(),
		})
		if err := s.Client.SubResource("approval").Update(ctx, csr); err != nil {
			return ctrl.Result{}, err
		}
	}
	ca, err := s.CA.Ensure(ctx)
	if err != nil {
		return ctrl.Result{}, err
	}
	cert, err := pki.Sign(ca[pki.CACert], ca[pki.CAKey], pub, Leaf(node, validity(csr)), s.now())
	if err != nil {
		return ctrl.Result{}, err
	}
	csr.Status.Certificate = cert
	if err := s.Client.SubResource("status").Update(ctx, csr); err != nil {
		return ctrl.Result{}, err
	}
	log.Info("signed an agent certificate", "node", node)
	return ctrl.Result{}, nil
}

// podNode looks up the node of the agent pod a token was bound to (in the
// agents' namespace, from AgentUser).
func (s *Signer) podNode(ctx context.Context) func(name, uid string) (string, error) {
	return func(name, uid string) (string, error) {
		ns := strings.TrimPrefix(s.AgentUser, "system:serviceaccount:")
		ns, _, _ = strings.Cut(ns, ":")
		pod := &corev1.Pod{}
		if err := s.Client.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, pod); err != nil {
			return "", fmt.Errorf("the requester's pod %s/%s: %w", ns, name, err)
		}
		if string(pod.UID) != uid {
			return "", fmt.Errorf("the requester's pod %s/%s is gone (UID %s, token for %s)", ns, name, pod.UID, uid)
		}
		if pod.Spec.NodeName == "" {
			return "", fmt.Errorf("the requester's pod %s/%s has no node", ns, name)
		}
		return pod.Spec.NodeName, nil
	}
}

// Leaf is the certificate of node: its name as common name and DNS name,
// for both ends of a connection.
func Leaf(node string, validity time.Duration) pki.Leaf {
	return pki.Leaf{CommonName: node, DNSNames: []string{node},
		Usages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, Validity: validity}
}

// Validate checks a request against the requester: the agents' service
// account with a token bound to a pod on the node the request names, and
// nothing in it beyond that name.
func Validate(csr *certv1.CertificateSigningRequest, agentUser string, podNode func(name, uid string) (string, error)) (
	string, *ecdsa.PublicKey, error) {
	if csr.Spec.Username != agentUser {
		return "", nil, fmt.Errorf("requested by %q, not by the agents (%s)", csr.Spec.Username, agentUser)
	}
	node, err := requesterNode(csr.Spec.Extra, podNode)
	if err != nil {
		return "", nil, err
	}
	for _, u := range csr.Spec.Usages {
		if !slices.Contains(allowedUsages, u) {
			return "", nil, fmt.Errorf("usage %q not allowed", u)
		}
	}
	block, _ := pem.Decode(csr.Spec.Request)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return "", nil, errors.New("no PEM certificate request")
	}
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", nil, err
	}
	if err := req.CheckSignature(); err != nil {
		return "", nil, fmt.Errorf("request signature: %w", err)
	}
	if req.Subject.CommonName != node {
		return "", nil, fmt.Errorf("common name %q is not the requester's node %q", req.Subject.CommonName, node)
	}
	if len(req.DNSNames) > 1 || (len(req.DNSNames) == 1 && req.DNSNames[0] != node) ||
		len(req.IPAddresses)+len(req.EmailAddresses)+len(req.URIs) > 0 {
		return "", nil, errors.New("the request may name only the node")
	}
	pub, ok := req.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return "", nil, errors.New("key must be ECDSA P-256")
	}
	return node, pub, nil
}

// requesterNode is the node the requester's token is bound to: its
// node-name extra (Kubernetes >= 1.30), else the node of its pod.
func requesterNode(extra map[string]certv1.ExtraValue, podNode func(name, uid string) (string, error)) (string, error) {
	if nodes := extra[NodeNameExtra]; len(nodes) == 1 && nodes[0] != "" {
		return nodes[0], nil
	}
	names, uids := extra[podNameExtra], extra[podUIDExtra]
	if len(names) != 1 || len(uids) != 1 || podNode == nil {
		return "", errors.New("the requester's token is bound to no pod (a pod-bound token is needed)")
	}
	return podNode(names[0], uids[0])
}

func validity(csr *certv1.CertificateSigningRequest) time.Duration {
	v := MaxValidity
	if e := csr.Spec.ExpirationSeconds; e != nil {
		v = min(v, time.Duration(*e)*time.Second)
	}
	return max(v, minValidity)
}

func condition(csr *certv1.CertificateSigningRequest, t certv1.RequestConditionType) bool {
	for _, c := range csr.Status.Conditions {
		if c.Type == t && c.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

// Publish keeps the CA (renewed in time) and its bundle in the ConfigMap.
func (s *Signer) Publish(ctx context.Context) error {
	ca, err := s.CA.Ensure(ctx)
	if err != nil {
		return err
	}
	cm := &corev1.ConfigMap{}
	err = s.Client.Get(ctx, s.Bundle, cm)
	switch {
	case apierrors.IsNotFound(err):
		cm = &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: s.Bundle.Name, Namespace: s.Bundle.Namespace,
				Labels: map[string]string{"app.kubernetes.io/managed-by": "paguro"}},
			Data: map[string]string{CAFile: string(ca[pki.CACert])},
		}
		return s.Client.Create(ctx, cm)
	case err != nil:
		return err
	case bytes.Equal([]byte(cm.Data[CAFile]), ca[pki.CACert]):
		return nil
	}
	cm.Data = map[string]string{CAFile: string(ca[pki.CACert])}
	return s.Client.Update(ctx, cm)
}

// Start republishes hourly (manager.Runnable, leader only).
func (s *Signer) Start(ctx context.Context) error {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := s.Publish(ctx); err != nil {
				logf.FromContext(ctx).Error(err, "publishing the agents' CA")
			}
		}
	}
}

func (s *Signer) NeedLeaderElection() bool { return true }
