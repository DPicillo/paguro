# SPDX-License-Identifier: AGPL-3.0-only
# Supply chain and release targets (included by the Makefile via -include).
#
#   make vulncheck                     # govulncheck with reviewed exceptions
#   make release PAGURO_REGISTRY=ghcr.io/<owner>/paguro TAG=v0.1.0 \
#                CHART_REGISTRY=oci://ghcr.io/<owner>/charts
#
# release = images-push + installer sources + sbom + sign + chart-push +
# artifacthub-push.
# The single steps work on images already in PAGURO_REGISTRY:
#
#   make sbom      # SPDX JSON per image (syft) into dist/sbom/
#   make sign      # cosign signature + signed SBOM attestation per image
#   make verify    # checks both
#   make image-scan  # grype: fails on fixable vulnerabilities >= high
#                    # (reviewed exceptions: .grype.yaml)
#   make chart-push  # Helm chart to CHART_REGISTRY, signed like the images
#   make artifacthub-push # artifacthub-repo.yml as CHART_REGISTRY/paguro:artifacthub.io
#   make plugin-dist # kubectl-paguro for Linux, macOS and Windows into dist/
#
# SIGN=false pushes the chart unsigned: keyless signatures are recorded in
# Sigstore's public transparency log, which names the repository – the
# release workflow signs only once the repository is public.
#
# Signing is keyless (Sigstore: the OIDC identity of the CI job, logged in
# the public transparency log) unless COSIGN_KEY names a key (file or KMS
# URI); verify then needs COSIGN_PUB. A registry without TLS (the lab)
# needs COSIGN_FLAGS="--allow-http-registry --allow-insecure-registry",
# CRANE_FLAGS=--insecure, HELM_PUSH_FLAGS=--plain-http, ORAS_FLAGS=--plain-http
# and SYFT_REGISTRY_INSECURE_USE_HTTP=true / GRYPE_REGISTRY_INSECURE_USE_HTTP=true.

RELEASE_IMAGES := paguro-controller paguro-agent paguro-node-installer paguro-node-installer-sources
# Scanned and signed like the others; the sources image has no executables.
SCAN_IMAGES    := paguro-controller paguro-agent paguro-node-installer
SYFT           ?= syft
GRYPE          ?= grype
COSIGN         ?= cosign
ORAS           ?= oras
ORAS_FLAGS     ?=
DIST           ?= dist
COSIGN_KEY     ?=
COSIGN_PUB     ?=
COSIGN_FLAGS   ?=
# Keyless verification: who may have signed – the release workflow of this
# repository (GITHUB_REPOSITORY in a workflow, so that a fork verifies its own).
COSIGN_REPO     ?= $(or $(GITHUB_REPOSITORY),DPicillo/paguro)
COSIGN_IDENTITY ?= ^https://github\.com/$(subst .,\.,$(COSIGN_REPO))/\.github/workflows/release\.yaml@refs/tags/v.+$$
COSIGN_ISSUER   ?= https://token.actions.githubusercontent.com
CHART_REGISTRY ?=
CHART_VERSION  ?= $(patsubst v%,%,$(TAG))
GRYPE_FAIL_ON  ?= high
SIGN           ?= true
PLUGIN_TARGETS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: vulncheck sbom sign verify image-scan chart-package chart-push chart-sign release installer-sources-push plugin-dist \
        artifacthub-push

vulncheck:
	hack/vulncheck.sh

# Image reference by digest: signatures and attestations bind to content,
# never to a tag.
image-ref = $(PAGURO_REGISTRY)/$(1)@$$($(CRANE) digest $(CRANE_FLAGS) $(PAGURO_REGISTRY)/$(1):$(TAG))

cosign-key = $(if $(COSIGN_KEY),--key $(COSIGN_KEY) --tlog-upload=false --use-signing-config=false,)
cosign-verify = $(if $(COSIGN_PUB),--key $(COSIGN_PUB) --insecure-ignore-tlog=true,--certificate-identity-regexp '$(COSIGN_IDENTITY)' --certificate-oidc-issuer $(COSIGN_ISSUER))

installer-sources-push: installer-sources
	$(CONTAINER_TOOL) push $(PAGURO_REGISTRY)/paguro-node-installer-sources:$(TAG)

sbom:
	@mkdir -p $(DIST)/sbom
	@for n in $(RELEASE_IMAGES); do \
	  ref=$(call image-ref,$$n) || exit 1; \
	  echo "sbom $$ref"; \
	  $(SYFT) scan -q "registry:$$ref" -o spdx-json=$(DIST)/sbom/$$n.spdx.json || exit 1; \
	done

sign: sbom
	@for n in $(RELEASE_IMAGES); do \
	  ref=$(call image-ref,$$n) || exit 1; \
	  echo "sign $$ref"; \
	  $(COSIGN) sign --yes $(cosign-key) $(COSIGN_FLAGS) "$$ref" || exit 1; \
	  $(COSIGN) attest --yes $(cosign-key) $(COSIGN_FLAGS) --type spdxjson \
	    --predicate $(DIST)/sbom/$$n.spdx.json "$$ref" || exit 1; \
	done

verify:
	@for n in $(RELEASE_IMAGES); do \
	  ref=$(call image-ref,$$n) || exit 1; \
	  $(COSIGN) verify $(cosign-verify) $(COSIGN_FLAGS) "$$ref" >/dev/null || exit 1; \
	  $(COSIGN) verify-attestation $(cosign-verify) $(COSIGN_FLAGS) --type spdxjson "$$ref" >/dev/null || exit 1; \
	  echo "verified: $$ref (signature, SBOM attestation)"; \
	done

image-scan:
	@for n in $(SCAN_IMAGES); do \
	  ref=$(call image-ref,$$n) || exit 1; \
	  echo "scan $$ref"; \
	  $(GRYPE) -q -c .grype.yaml "registry:$$ref" --only-fixed --fail-on $(GRYPE_FAIL_ON) || exit 1; \
	done

chart-package: helm-crds
	@mkdir -p $(DIST)
	$(HELM) package $(CHART) --version $(CHART_VERSION) --app-version $(TAG) -d $(DIST)

# helm push prints the chart's digest; the signature binds to it.
chart-push: chart-package
	@test -n "$(CHART_REGISTRY)" || { echo "CHART_REGISTRY (oci://...) not set" >&2; exit 1; }
	@$(HELM) push $(DIST)/paguro-$(CHART_VERSION).tgz $(CHART_REGISTRY) $(HELM_PUSH_FLAGS) > $(DIST)/chart-push.txt 2>&1; \
	  rc=$$?; cat $(DIST)/chart-push.txt; exit $$rc
	@digest=$$(sed -n 's/^Digest: //p' $(DIST)/chart-push.txt); \
	  test -n "$$digest" || { echo "no chart digest in helm's output" >&2; exit 1; }; \
	  ref=$(patsubst oci://%,%,$(CHART_REGISTRY))/paguro@$$digest; \
	  if [ "$(SIGN)" = false ]; then echo "not signed (SIGN=false): $$ref"; exit 0; fi; \
	  echo "sign $$ref"; \
	  $(COSIGN) sign --yes $(cosign-key) $(COSIGN_FLAGS) "$$ref"

# Artifact Hub's repository metadata: artifacthub-repo.yml, whose repository
# ID makes Artifact Hub show the chart as from a verified publisher. For an
# OCI repository Artifact Hub reads it from the tag "artifacthub.io" next
# to the chart, an artifact with exactly these media types
# (https://artifacthub.io/docs/topics/repositories/helm-charts/#oci-support).
# Pushed again with every release: the content is the same, the tag moves.
# Skipped while the file holds the all-zero placeholder ID.
artifacthub-push:
	@test -n "$(CHART_REGISTRY)" || { echo "CHART_REGISTRY (oci://...) not set" >&2; exit 1; }
	@if grep -q '^repositoryID: 00000000-' artifacthub-repo.yml; then \
	  echo "artifacthub-repo.yml has no repository ID yet – not pushed"; exit 0; fi; \
	  ref=$(patsubst oci://%,%,$(CHART_REGISTRY))/paguro:artifacthub.io; \
	  echo "push $$ref"; \
	  $(ORAS) push $(ORAS_FLAGS) "$$ref" \
	    --config /dev/null:application/vnd.cncf.artifacthub.config.v1+yaml \
	    artifacthub-repo.yml:application/vnd.cncf.artifacthub.repository-metadata.layer.v1.yaml

# The kubectl plugin as release assets: one archive per platform (binary
# and LICENSE) and their SHA-256 sums.
plugin-dist:
	@mkdir -p $(DIST)/plugin
	@set -e; for t in $(PLUGIN_TARGETS); do \
	  os=$${t%/*}; arch=$${t#*/}; ext=; [ $$os = windows ] && ext=.exe; \
	  dir=$(DIST)/plugin/kubectl-paguro_$(TAG)_$${os}_$${arch}; mkdir -p $$dir; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags="-s -w -X main.version=$(TAG)" -o $$dir/kubectl-paguro$$ext ./cmd/kubectl-paguro; \
	  cp LICENSE $$dir/; \
	  tar -C $(DIST)/plugin -czf $$dir.tar.gz $$(basename $$dir); rm -r $$dir; \
	done
	cd $(DIST)/plugin && sha256sum *.tar.gz > kubectl-paguro_$(TAG)_checksums.txt

release: images-push installer-sources-push sign chart-push artifacthub-push
