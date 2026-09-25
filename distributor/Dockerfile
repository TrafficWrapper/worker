# syntax=docker/dockerfile:1
FROM nginx:1.30-alpine@sha256:985220252f3863977e468f611ef118ebd01421289dd86ee1ae99cb068c3bce2b

RUN apk add --no-cache iproute2

COPY nginx.conf.template /etc/nginx/templates/worker.conf.template
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
