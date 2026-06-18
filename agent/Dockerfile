FROM golang:1.23.12-bookworm AS build

WORKDIR /src
COPY core ./core
COPY agent ./agent

WORKDIR /src/agent
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o /out/worker-agent ./cmd/agent

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/worker-agent /usr/local/bin/worker-agent

ENTRYPOINT ["/usr/local/bin/worker-agent"]
