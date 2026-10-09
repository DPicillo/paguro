# SPDX-License-Identifier: AGPL-3.0-only
# Node installer and Helm chart targets (included by the Makefile via -include).
#
#   make installer-image PAGURO_REGISTRY=registry.example.com/paguro TAG=v0.1.0
#   make installer-test                 # fake host roots, no cluster needed
#   make images-push                    # agent + controller + installer
#   make helm-lint helm-template
#   make helm-install PAGURO_REGISTRY=... TAG=...
#
# The chart (deploy/helm/paguro) derives image names as
# <global.imageRegistry>/<name>:<global.imageTag>, so one PAGURO_REGISTRY/TAG
# pair covers all three images.

INSTALLER_IMAGE := $(PAGURO_REGISTRY)/paguro-node-installer:$(TAG)
CRIU_VERSION    ?= 4.2.1
CRICTL_VERSION  ?= v1.37.0
HELM            ?= helm
CHART           := deploy/helm/paguro
HELM_NAMESPACE  ?= paguro-system
HELM_ARGS       ?=

.PHONY: installer-image installer-push installer-test installer-sources \
        images-push helm-crds helm-lint helm-template helm-install helm-uninstall

installer-image:
	$(CONTAINER_TOOL) build -f build/node-installer.Dockerfile \
	  --build-arg CRIU_VERSION=$(CRIU_VERSION) --build-arg CRICTL_VERSION=$(CRICTL_VERSION) \
	  -t $(INSTALLER_IMAGE) .

installer-push: installer-image
	$(CONTAINER_TOOL) push $(INSTALLER_IMAGE)

# Runs the installer image against fake host roots (kubeadm v3 without
# imports, v3 with imports, EKS AL2023 v3/v2, a managed v4 config, no config) with
# containerd 2.0/2.1/2.4: idempotency, TOML validity, uninstall.
installer-test: installer-image
	build/node-installer/test-fakeroot.sh $(INSTALLER_IMAGE)

# The complete corresponding source of the installer's GPL/LGPL bundle
# (CRIU + patches, Ubuntu source packages), published next to every
# installer image with the same tag (docs/THIRD-PARTY.md).
installer-sources:
	$(CONTAINER_TOOL) build -f build/node-installer.Dockerfile --target sources \
	  --build-arg CRIU_VERSION=$(CRIU_VERSION) -t $(PAGURO_REGISTRY)/paguro-node-installer-sources:$(TAG) .

images-push: controller-push installer-push
	$(CONTAINER_TOOL) build -f build/agent.Dockerfile -t $(AGENT_IMAGE) .
	$(CONTAINER_TOOL) push $(AGENT_IMAGE)

# Keep the chart's CRDs in sync with deploy/crds (run after `make generate`).
# The CRD is a chart template (templates/crds.yaml reads files/crds/), not
# in crds/: Helm installs crds/ once and never upgrades it, so new status
# fields would be pruned silently after an upgrade.
helm-crds:
	mkdir -p $(CHART)/files/crds
	cp deploy/crds/*.yaml $(CHART)/files/crds/

helm-lint: helm-crds
	$(HELM) lint $(CHART) --strict

helm-template:
	$(HELM) template paguro $(CHART) -n $(HELM_NAMESPACE) \
	  --set global.imageRegistry=$(PAGURO_REGISTRY) --set global.imageTag=$(TAG) $(HELM_ARGS)

helm-install: helm-crds
	$(HELM) upgrade --install paguro $(CHART) -n $(HELM_NAMESPACE) --create-namespace \
	  --set global.imageRegistry=$(PAGURO_REGISTRY) --set global.imageTag=$(TAG) $(HELM_ARGS)
	$(KUBECTL) -n $(HELM_NAMESPACE) rollout status ds/paguro-agent --timeout=600s
	$(KUBECTL) -n $(HELM_NAMESPACE) rollout status deploy/paguro-controller --timeout=300s

helm-uninstall:
	$(HELM) uninstall paguro -n $(HELM_NAMESPACE)
