FROM nginx:1.27-alpine

RUN apk add --no-cache iproute2

COPY nginx.conf.template /etc/nginx/templates/worker.conf.template
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
