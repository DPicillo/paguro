# SPDX-License-Identifier: AGPL-3.0-only
# paguro-agent + paguro-runc
# The agent image contains nsenter (util-linux): host programs (runc, criu,
# nft, crictl) run in the host's mount namespace so that they have exactly
# containerd's view. paguro-runc is copied to the host at startup.
FROM golang:1.26.9 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/paguro-agent ./cmd/paguro-agent && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/paguro-runc ./cmd/paguro-runc

FROM alpine:3.24
# apk upgrade: the base image's packages with the fixes published since the
# tag was built (make image-scan fails on fixable vulnerabilities).
RUN apk upgrade --no-cache && apk add --no-cache util-linux-misc ca-certificates
COPY --from=build /out/paguro-agent /out/paguro-runc /usr/local/bin/
COPY LICENSE docs/THIRD-PARTY.md third_party/LICENSES.txt /licenses/
LABEL org.opencontainers.image.licenses="AGPL-3.0-only"
ENTRYPOINT ["/usr/local/bin/paguro-agent"]
