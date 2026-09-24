# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.24-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY core/go.mod core/go.sum ./core/
COPY awg-smoke/go.mod awg-smoke/go.sum ./awg-smoke/
WORKDIR /src/awg-smoke
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
WORKDIR /src
COPY core ./core
COPY awg-smoke ./awg-smoke
WORKDIR /src/awg-smoke
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/awg-smoke ./cmd/awg-smoke

FROM debian:13-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/awg-smoke /usr/local/bin/awg-smoke
ENTRYPOINT ["/usr/local/bin/awg-smoke"]
