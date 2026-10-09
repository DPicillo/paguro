# SPDX-License-Identifier: AGPL-3.0-only
# Paguro – build and deployment.
#
#   make controller-image PAGURO_REGISTRY=registry.example.com/paguro TAG=v0.1.0
#   make helm-install PAGURO_REGISTRY=... TAG=...   (build/installer.mk)
#
# Other components (agent, node installer, release) have their targets in
# build/*.mk.

PAGURO_REGISTRY ?= localhost:5000/paguro
TAG             ?= dev
GO              ?= go
KUBECTL         ?= kubectl
CONTAINER_TOOL  ?= docker

CONTROLLER_IMAGE := $(PAGURO_REGISTRY)/paguro-controller:$(TAG)

.PHONY: all test vet lint generate bpf-generate controller controller-image controller-push \
        kubectl-plugin ci fmt-check headers-check generate-check tools chart-docs

all: vet test controller kubectl-plugin

vet:
	$(GO) vet ./...

# Unit tests. The datapath tests that need root and a real kernel skip
# themselves here; run them on a node: go test -c ./internal/phantom/ and
# sudo ./phantom.test (see docs/PHANTOM-MODE.md, section 15).
test:
	$(GO) test ./...

# bpf/phantom.c changed → regenerate the eBPF object (bpf2go) in a container,
# so that no local clang is needed.
bpf-generate:
	$(CONTAINER_TOOL) run --rm -v $(CURDIR):/src -w /src golang:1.26 sh -c '\
	  apt-get update -qq && apt-get install -y -qq clang llvm >/dev/null && \
	  git config --global --add safe.directory /src; \
	  go generate ./internal/phantom/ && chown $(shell id -u):$(shell id -g) internal/phantom/phantom_bpfel.*'
	@# bpf2go writes no license header; hack/check-headers.sh wants one.
	@f=internal/phantom/phantom_bpfel.go; head -3 $$f | grep -q SPDX-License-Identifier || \
	  { printf '// SPDX-License-Identifier: AGPL-3.0-only\n// Copyright (C) 2026 David Picillo\n\n' | cat - $$f > $$f.tmp && mv $$f.tmp $$f; }

# Everything CI checks (.github/workflows/ci.yaml), runnable locally.
ci: fmt-check headers-check vet lint test generate-check helm-lint

# staticcheck: dead code, deprecated APIs, simplifications. Pinned, so that
# a new release cannot fail an old commit.
STATICCHECK_VERSION ?= 2026.2.1
lint:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...

fmt-check:
	@out=$$(gofmt -l $$(git ls-files '*.go')); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

headers-check:
	hack/check-headers.sh

# Generated files (DeepCopy, CRDs, chart CRDs, third-party licenses, the
# values tables of the chart's README) must be up to date: regenerating
# changes nothing. Compares the working tree before and after, so
# uncommitted work does not count as stale.
GENERATED := api deploy/crds deploy/helm/paguro/files deploy/helm/paguro/README.md docs/THIRD-PARTY.md third_party
generate-check:
	@before=$$(git diff -- $(GENERATED) | sha256sum; git ls-files -o --exclude-standard -- $(GENERATED) | xargs -r cat | sha256sum); \
	  $(MAKE) -s generate >/dev/null && $(GO) run ./hack/thirdparty >/dev/null && $(GO) run ./hack/chartdocs || exit 1; \
	  after=$$(git diff -- $(GENERATED) | sha256sum; git ls-files -o --exclude-standard -- $(GENERATED) | xargs -r cat | sha256sum); \
	  if [ "$$before" != "$$after" ]; then echo "generated files were stale – regenerated, review and commit:"; \
	    git status --short -- $(GENERATED); exit 1; fi

CONTROLLER_GEN_VERSION ?= v0.22.0
tools:
	$(GO) install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_GEN_VERSION)

# The values tables of the chart's README, from values.yaml and
# values.schema.json (hack/chartdocs).
chart-docs:
	$(GO) run ./hack/chartdocs

# API types changed → regenerate DeepCopy and CRD.
generate:
	controller-gen object:headerFile=hack/boilerplate.go.txt paths=./api/...
	controller-gen crd paths=./api/... output:crd:dir=deploy/crds
	$(MAKE) helm-crds

controller:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w -X main.version=$(TAG)" -o bin/paguro-controller ./cmd/paguro-controller

kubectl-plugin:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w -X main.version=$(TAG)" -o bin/kubectl-paguro ./cmd/kubectl-paguro

controller-image:
	$(CONTAINER_TOOL) build -f build/controller.Dockerfile --build-arg VERSION=$(TAG) -t $(CONTROLLER_IMAGE) .

controller-push: controller-image
	$(CONTAINER_TOOL) push $(CONTROLLER_IMAGE)

-include build/*.mk
