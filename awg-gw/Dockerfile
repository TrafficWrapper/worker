# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.24-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src
COPY core/go.mod core/go.sum ./core/
COPY awg-gw/go.mod awg-gw/go.sum ./awg-gw/

WORKDIR /src/awg-gw
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

WORKDIR /src
COPY core ./core
COPY awg-gw ./awg-gw

WORKDIR /src/awg-gw
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X github.com/amnezia-vpn/amneziawg-go/ipc.socketDirectory=/var/run/wireguard" \
    -o /out/awg-gw ./cmd/awg-gw

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS run

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 nftables \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/awg-gw /usr/local/bin/awg-gw

ENTRYPOINT ["/usr/local/bin/awg-gw"]
