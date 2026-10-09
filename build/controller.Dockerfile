# SPDX-License-Identifier: AGPL-3.0-only
# paguro-controller – the build context is the repo root:
#   docker build -f build/controller.Dockerfile -t <registry>/paguro-controller:<tag> .
FROM golang:1.26.9 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY api/ api/
COPY pkg/ pkg/
COPY internal/ internal/
COPY cmd/paguro-controller/ cmd/paguro-controller/
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/paguro-controller ./cmd/paguro-controller

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/paguro-controller /paguro-controller
COPY LICENSE docs/THIRD-PARTY.md third_party/LICENSES.txt /licenses/
LABEL org.opencontainers.image.licenses="AGPL-3.0-only"
USER 65532:65532
ENTRYPOINT ["/paguro-controller"]
