# SPDX-License-Identifier: AGPL-3.0-only
# Agent targets (included by the Makefile via -include).
#
#   make agent-image PAGURO_REGISTRY=registry.example.com/paguro TAG=v0.1.0
#   make images-crane-push PUSH_REGISTRY=registry.example.com:5000 TAG=v0.1.0

AGENT_IMAGE := $(PAGURO_REGISTRY)/paguro-agent:$(TAG)
CRANE ?= crane

.PHONY: agent agent-image images-crane-push

agent:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o bin/paguro-agent ./cmd/paguro-agent
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o bin/paguro-runc ./cmd/paguro-runc

agent-image:
	$(CONTAINER_TOOL) build -f build/agent.Dockerfile -t $(AGENT_IMAGE) .

# For registries without TLS (development clusters): builds all images and
# pushes them with crane to PUSH_REGISTRY – the address this machine
# reaches the registry under, which may differ from the cluster's
# PAGURO_REGISTRY. Nodes pull with IfNotPresent, so a reused tag would run
# whatever a node cached under it earlier: tags the registry already has
# are refused.
images-crane-push:
	@test -n "$(PUSH_REGISTRY)" || { echo "PUSH_REGISTRY is required (host:port of the registry)" >&2; exit 1; }
	@for n in paguro-agent paguro-controller paguro-node-installer; do \
	  if $(CRANE) digest --insecure $(PUSH_REGISTRY)/$$n:$(TAG) >/dev/null 2>&1; then \
	    echo "$(PUSH_REGISTRY)/$$n:$(TAG) exists already – nodes may run a cached old image; use a new TAG" >&2; exit 1; \
	  fi; \
	done
	@mkdir -p bin/images
	$(CONTAINER_TOOL) build -q -f build/agent.Dockerfile -t paguro-agent:$(TAG) .
	$(CONTAINER_TOOL) build -q -f build/controller.Dockerfile --build-arg VERSION=$(TAG) -t paguro-controller:$(TAG) .
	$(CONTAINER_TOOL) build -q -f build/node-installer.Dockerfile -t paguro-node-installer:$(TAG) .
	$(CONTAINER_TOOL) build -q -f build/node-installer.Dockerfile --target sources -t paguro-node-installer-sources:$(TAG) .
	for n in paguro-agent paguro-controller paguro-node-installer paguro-node-installer-sources; do \
	  $(CONTAINER_TOOL) save $$n:$(TAG) -o bin/images/$$n.tar && \
	  $(CRANE) push --insecure bin/images/$$n.tar $(PUSH_REGISTRY)/$$n:$(TAG) || exit 1; \
	done
