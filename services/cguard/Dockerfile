FROM node:20-alpine

RUN apk add --no-cache wget postgresql-client

WORKDIR /app

COPY package.json ./
COPY server/ ./server/
COPY shared/ ./shared/
COPY admin/investigationView.js ./admin/investigationView.js
COPY db/ ./db/

EXPOSE 8500

CMD ["node", "server/start.js"]
