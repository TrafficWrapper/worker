# Pinned by digest for reproducible builds; bump both together.
# The agent relies on `xray api adu/rmu/statsquery` from this release.
FROM ghcr.io/xtls/xray-core:26.3.27@sha256:592ec4d11f656db95598d01e76dbcc6e002d67360b96a5436500a938230f52c7 AS xray

FROM alpine:3.21

COPY --from=xray /usr/local/bin/xray /usr/local/bin/xray
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
