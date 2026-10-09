#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 David Picillo
#
# Kubernetes version matrix: installs the chart on a kind cluster per
# version and checks what depends on the API server – install, webhook,
# CRD validation, preflight, admission policies, commit gate (DRA), the
# agents' certificate requests. Not a migration test: kind nodes cannot
# checkpoint (the lab runs those).
#
#   hack/version-matrix.sh TAG [versions...]     (images <name>:TAG in the local docker)
#
# Uses its own kubeconfig only; never touches ~/.kube/config.
set -u
tag=$1; shift
versions=${*:-v1.28.15 v1.29.14 v1.30.13 v1.31.14 v1.32.11 v1.33.12 v1.34.11 v1.35.8 v1.36.4 v1.37.0}
cd "$(dirname "$0")/.."
work=$(mktemp -d)
export KUBECONFIG=$work/kubeconfig
reg=paguro.local
for n in paguro-controller paguro-agent paguro-node-installer; do
  docker tag "$n:$tag" "$reg/$n:$tag" || exit 1
done

check() { # name command...
  if out=$("${@:2}" 2>&1); then echo "  ok   $1"; else echo "  FAIL $1: $(echo "$out" | tail -2 | tr '\n' ' ' | cut -c1-200)"; return 1; fi
}

for v in $versions; do
  name=pm-${v//./-}
  echo "== $v"
  if ! kind create cluster --name "$name" --image "kindest/node:$v" --wait 120s >"$work/$name.log" 2>&1; then
    echo "  FAIL kind: $(tail -2 "$work/$name.log" | tr '\n' ' ')"; continue
  fi
  for n in paguro-controller paguro-agent paguro-node-installer; do
    kind load docker-image --name "$name" "$reg/$n:$tag" >/dev/null 2>&1
  done
  minor=$(echo "$v" | cut -d. -f2)
  check "helm install" helm install paguro deploy/helm/paguro -n paguro-system --create-namespace \
    --set global.imageRegistry=$reg --set global.imageTag=$tag --set controller.replicas=1 \
    --set nodeInstaller.enabled=false --wait --timeout 4m
  check "controller ready" kubectl -n paguro-system rollout status deploy/paguro-controller --timeout=120s
  # The webhook mutates a migratable pod (whether it can start is the node's business).
  kubectl create ns pm-test >/dev/null 2>&1
  # The webhook mutates a migratable pod (whether it can start is the
  # node's business). Right after the install the API server may not reach
  # it yet (failurePolicy Ignore): retry for 30 s and report when it did.
  check "webhook mutates" sh -c 'for i in $(seq 1 15); do
      kubectl -n pm-test run web$i --image=registry.k8s.io/pause:3.10 --labels=paguro.dev/migratable=true >/dev/null || exit 1
      if [ "$(kubectl -n pm-test get pod web$i -o jsonpath={.spec.runtimeClassName})" = paguro ]; then
        kubectl -n pm-test label pod web$i run=web --overwrite >/dev/null; echo "attempt $i"; exit 0; fi
      kubectl -n pm-test delete pod web$i --wait=false >/dev/null; sleep 2; done; exit 1' ||
    echo "       webhook: $(kubectl get mutatingwebhookconfiguration paguro -o jsonpath='{.webhooks[0].failurePolicy}' 2>&1 | cut -c1-100)"
  web=$(kubectl -n pm-test get pods -l run=web -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  # Status writes pass the CRD's validation; the preflight explains itself.
  check "preflight + CRD" sh -c 'printf "apiVersion: paguro.dev/v1alpha1\nkind: Migration\nmetadata: {name: m, namespace: pm-test}\nspec: {podName: '"${web:-web1}"'}\n" | kubectl create -f - >/dev/null &&
    for i in $(seq 1 30); do p=$(kubectl -n pm-test get migration m -o jsonpath={.status.phase}); [ -n "$p" ] && [ "$p" != Pending ] && [ "$p" != Preflight ] && break; sleep 2; done;
    kubectl -n pm-test get migration m -o jsonpath="{.status.phase}: {.status.message}" | grep -q "Failed: "'
  echo "       $(kubectl -n pm-test get migration m -o jsonpath='{.status.phase}: {.status.message}' 2>/dev/null | cut -c1-160)"
  vaps=$(kubectl get validatingadmissionpolicies -o name 2>/dev/null | grep -c paguro)
  if [ "$minor" -ge 30 ]; then
    check "admission policies ($vaps)" test "$vaps" -ge 6
    check "policy type checking" sh -c '! kubectl get validatingadmissionpolicies -o jsonpath="{range .items[*]}{.status.typeChecking}{end}" | grep -q expressionWarnings' ||
      kubectl get validatingadmissionpolicies -o jsonpath='{range .items[*]}{.metadata.name}: {.status.typeChecking.expressionWarnings[*].warning}{"\n"}{end}' | grep -v ': $' | cut -c1-300 | sed 's/^/       /'
  else
    echo "  --   admission policies: not before 1.30 ($vaps installed)"
  fi
  dc=$(kubectl get deviceclass gate.paguro.dev -o name 2>/dev/null)
  echo "  --   commit gate: ${dc:-no DeviceClass} (resource.k8s.io/v1 from 1.34)"
  check "controller log clean" sh -c '! kubectl -n paguro-system logs deploy/paguro-controller | grep -i "\"level\":\"error\"" | grep -v "Reconciler error" | head -3 | grep .'
  csr=$(kubectl get csr -o jsonpath='{range .items[*]}{.spec.signerName} {.status.conditions[0].type}{"\n"}{end}' 2>/dev/null | grep paguro.dev/agent | sort | uniq -c | tr '\n' ';')
  echo "  --   agent certificate requests: ${csr:-none}"
  echo "  --   agent pods: $(kubectl -n paguro-system get pods -l app.kubernetes.io/name=paguro-agent -o jsonpath='{range .items[*]}{.status.phase} {end}')"
  # Uninstall: only what INSTALL.md lists as left behind may stay.
  helm uninstall paguro -n paguro-system --wait --timeout 2m >/dev/null 2>&1
  kubectl -n paguro-system wait --for=delete pods --all --timeout=90s >/dev/null 2>&1
  left=$( (kubectl get validatingadmissionpolicies,validatingadmissionpolicybindings,mutatingwebhookconfigurations,clusterroles,clusterrolebindings,runtimeclasses,deviceclasses -o name 2>/dev/null | grep -i paguro;
           kubectl -n paguro-system get all,secrets,configmaps -o name 2>/dev/null | grep -v kube-root-ca) | sort | tr '\n' ' ')
  expected="configmap/paguro-agent-ca secret/paguro-agent-ca secret/paguro-webhook-tls "
  if [ "$left" = "$expected" ]; then echo "  ok   uninstall leaves only the documented objects"; else echo "  FAIL uninstall left: $left"; fi
  kind delete cluster --name "$name" >/dev/null 2>&1
done
rm -rf "$work"
