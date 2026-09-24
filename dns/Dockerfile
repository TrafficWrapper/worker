# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.24-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac AS build

ARG TARGETOS
ARG TARGETARCH
# v0.76.0 is the newest release that builds with Go 1.24.
ARG DNSPROXY_VERSION=v0.76.0

WORKDIR /src
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod init dnsbuild \
    && go get github.com/AdguardTeam/dnsproxy@${DNSPROXY_VERSION}
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/dnsproxy github.com/AdguardTeam/dnsproxy

FROM alpine:3.21@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507

RUN apk add --no-cache ca-certificates
COPY --from=build /out/dnsproxy /usr/local/bin/dnsproxy
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
