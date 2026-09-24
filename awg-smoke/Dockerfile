# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195 AS build
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
