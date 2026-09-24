# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.24-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src
COPY core/go.mod core/go.sum ./core/
COPY agent/go.mod agent/go.sum ./agent/

WORKDIR /src/agent
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

WORKDIR /src
COPY core ./core
COPY agent ./agent

WORKDIR /src/agent
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/worker-agent ./cmd/agent

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/worker-agent /usr/local/bin/worker-agent

ENTRYPOINT ["/usr/local/bin/worker-agent"]
