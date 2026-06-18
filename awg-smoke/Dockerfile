FROM golang:1.23.12-bookworm AS build
WORKDIR /src
COPY core/go.mod core/go.sum ./core/
COPY awg-smoke/go.mod ./awg-smoke/
WORKDIR /src/awg-smoke
RUN go mod download
WORKDIR /src
COPY core ./core
COPY awg-smoke ./awg-smoke
WORKDIR /src/awg-smoke
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/awg-smoke ./cmd/awg-smoke

FROM debian:12-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/awg-smoke /usr/local/bin/awg-smoke
ENTRYPOINT ["/usr/local/bin/awg-smoke"]
