# SPDX-License-Identifier: AGPL-3.0-only
# paguro-node-installer: prepares a Kubernetes node for Paguro.
# Runs as the first initContainer of the paguro-agent DaemonSet (privileged,
# hostPID, host root at /host). See build/node-installer/install.sh.
#
#   docker build -f build/node-installer.Dockerfile -t paguro-node-installer:dev .
#
# Contents of the image:
#   /opt/paguro/bin/{criu,nft}  self-contained bundle (own glibc + loader,
#   /opt/paguro/lib/*           see build/node-installer/bundle.sh)
#   /opt/paguro/bin/crictl      static upstream binary
#   /usr/local/bin/paguro-node-installer
#
# The bundle is built on Ubuntu 24.04 but does not depend on the host's
# glibc: it ships its own loader at the fixed path /opt/paguro/lib, so it runs
# on Ubuntu 22.04/24.04, Debian 12, RHEL 9 and Amazon Linux 2023 (glibc 2.34).

ARG UBUNTU_IMAGE=ubuntu:24.04
ARG ALPINE_IMAGE=alpine:3.24

FROM ${UBUNTU_IMAGE} AS criu
ARG CRIU_VERSION=4.2.1
ARG DEBIAN_FRONTEND=noninteractive
# gnutls (page-server TLS) and libdrm (amdgpu plugin) are deliberately left
# out: Paguro does not use them and every extra library is one more thing in
# the bundle. libnftables-dev is mandatory (network-lock nftables).
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git gcc make pkg-config python3 python3-protobuf python3-yaml \
      libprotobuf-dev libprotobuf-c-dev protobuf-c-compiler protobuf-compiler \
      libcap-dev libnl-3-dev libnet1-dev libnftables-dev libbsd-dev uuid-dev \
      nftables patchelf file \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch v${CRIU_VERSION} https://github.com/checkpoint-restore/criu.git /src/criu
WORKDIR /src/criu
# Paguro's CRIU fixes (build/criu-patches/, also for CRIU built by hand). Most
# important: lazy-pages restore of pages that live in pre-dump parent images
# (without it a post-copy restore after pre-copy hangs on the first fault).
COPY build/criu-patches/ /src/criu-patches/
RUN for p in /src/criu-patches/*.patch; do git apply --check "$p" && git apply "$p" && echo "applied $p"; done && \
    cat /src/criu-patches/*.patch | sha256sum | cut -d' ' -f1 > /src/criu-patches.sha256
RUN make -j"$(nproc)" criu 2>&1 | tee /tmp/criu-build.log && \
    if grep -q "without nftables" /tmp/criu-build.log; then \
      echo "CRIU was built without nftables support - check libnftables-dev" >&2; exit 1; fi && \
    ./criu/criu --version | grep -q "Version: ${CRIU_VERSION}"
COPY build/node-installer/bundle.sh /usr/local/bin/bundle.sh
RUN strip /src/criu/criu/criu && \
    bash /usr/local/bin/bundle.sh /opt/paguro /src/criu/criu/criu /usr/sbin/nft && \
    bash /usr/local/bin/bundle.sh --licenses /licenses/bundle /usr/sbin/nft && \
    cp /src/criu/COPYING /licenses/bundle/criu.COPYING && \
    cp /src/criu-patches.sha256 /opt/paguro/criu-patches.sha256 && \
    /opt/paguro/bin/criu --version && /opt/paguro/bin/nft --version && \
    file /opt/paguro/bin/criu

# Complete corresponding source of the bundle (GPL/LGPL): CRIU at its tag
# plus Paguro's patches, and the Ubuntu source packages of every library and
# program in /opt/paguro. Published as paguro-node-installer-sources
# (`make installer-sources`); see docs/THIRD-PARTY.md.
FROM criu AS sources-collect
RUN sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources && \
    apt-get update && apt-get install -y --no-install-recommends dpkg-dev && \
    mkdir -p /sources/ubuntu /sources/criu && cd /sources/ubuntu && \
    for f in /opt/paguro/lib/* /usr/sbin/nft; do \
      n=$(basename "$f"); p=$(dpkg -S "*/$n" 2>/dev/null | head -1 | cut -d: -f1); \
      [ -n "$p" ] && dpkg-query -W -f='${source:Package}=${source:Version}\n' "$p"; \
    done | sort -u > /sources/ubuntu/PACKAGES && \
    xargs -a /sources/ubuntu/PACKAGES apt-get source --download-only && \
    rm -rf /var/lib/apt/lists/*
RUN cd /src/criu && git archive --format=tar.gz --prefix=criu-${CRIU_VERSION}/ HEAD > /sources/criu/criu-${CRIU_VERSION}.tar.gz && \
    cp -r /src/criu-patches /sources/criu/patches && \
    printf 'CRIU %s from https://github.com/checkpoint-restore/criu (tag v%s),\nbuilt with the patches in patches/ (git apply, in order) as in\nbuild/node-installer.Dockerfile of Paguro.\n' "${CRIU_VERSION}" "${CRIU_VERSION}" > /sources/criu/README

FROM scratch AS sources
COPY --from=sources-collect /sources/ /sources/
COPY LICENSE docs/THIRD-PARTY.md /sources/

FROM ${UBUNTU_IMAGE} AS crictl
ARG CRICTL_VERSION=v1.37.0
ARG TARGETARCH=amd64
ADD https://github.com/kubernetes-sigs/cri-tools/releases/download/${CRICTL_VERSION}/crictl-${CRICTL_VERSION}-linux-${TARGETARCH}.tar.gz /tmp/crictl.tgz
ADD https://github.com/kubernetes-sigs/cri-tools/releases/download/${CRICTL_VERSION}/crictl-${CRICTL_VERSION}-linux-${TARGETARCH}.tar.gz.sha256 /tmp/crictl.tgz.sha256
RUN echo "$(cat /tmp/crictl.tgz.sha256 | cut -d' ' -f1)  /tmp/crictl.tgz" | sha256sum -c - && \
    mkdir -p /out && tar -xzf /tmp/crictl.tgz -C /out crictl

FROM ${ALPINE_IMAGE}
ARG CRIU_VERSION=4.2.1
# bash: installer script; util-linux-misc/flock: nsenter, flock -w;
# coreutils: GNU stat/sort -V.
# apk upgrade: fixes published since the base image was built.
RUN apk upgrade --no-cache && apk add --no-cache bash util-linux-misc flock coreutils diffutils
COPY --from=criu /opt/paguro/ /opt/paguro/
COPY --from=crictl /out/crictl /opt/paguro/bin/crictl
COPY build/node-installer/install.sh /usr/local/bin/paguro-node-installer
COPY LICENSE docs/THIRD-PARTY.md third_party/LICENSES.txt /licenses/
COPY --from=criu /licenses/bundle/ /licenses/bundle/
# Manifest of the bundle: the installer compares it with the copy on the host
# and skips the file copy entirely when nothing changed (fast restarts).
RUN chmod 0755 /usr/local/bin/paguro-node-installer && \
    echo "criu ${CRIU_VERSION}" > /opt/paguro/VERSION && \
    cd /opt/paguro && find bin lib -type f | sort | xargs sha256sum > /opt/paguro/MANIFEST
LABEL org.opencontainers.image.licenses="AGPL-3.0-only AND GPL-2.0-only AND GPL-2.0-or-later AND LGPL-2.1-or-later AND Apache-2.0" \
      org.opencontainers.image.title="paguro-node-installer" \
      org.opencontainers.image.description="Installs CRIU, nftables and the paguro containerd runtime handler on Kubernetes nodes"
ENTRYPOINT ["/usr/local/bin/paguro-node-installer"]
