FROM nginx:alpine

RUN apk add --no-cache bash openssl

RUN rm -f /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/nginx.conf
COPY conf.d/cguard-admin.conf /etc/nginx/conf.d/cguard-admin.conf

RUN mkdir -p /etc/nginx/ssl /var/cache/nginx/scoreboard /var/www/scoreboard

COPY ssl/generate-certs.sh /docker-entrypoint.d/05-generate-ssl.sh
RUN chmod +x /docker-entrypoint.d/05-generate-ssl.sh

EXPOSE 80 443 8443
