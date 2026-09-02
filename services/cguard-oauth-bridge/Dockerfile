FROM node:20-alpine

WORKDIR /app

COPY package.json ./
COPY src ./src

ENV NODE_ENV=production
EXPOSE 8600

USER node

CMD ["node", "src/server.js"]
