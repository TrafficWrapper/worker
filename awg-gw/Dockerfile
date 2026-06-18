FROM golang:1.24-bookworm AS build

ARG VERSION=dev

WORKDIR /src
COPY core ./core
COPY awg-gw ./awg-gw

WORKDIR /src/awg-gw
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X github.com/amnezia-vpn/amneziawg-go/ipc.socketDirectory=/var/run/wireguard" \
    -o /out/awg-gw ./cmd/awg-gw

FROM debian:bookworm-slim AS run

RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 nftables \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/awg-gw /usr/local/bin/awg-gw

ENTRYPOINT ["/usr/local/bin/awg-gw"]
