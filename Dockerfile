FROM node:alpine

WORKDIR /app

RUN apk add --no-cache bash wget curl procps

COPY package*.json ./
RUN npm ci --only=production

COPY . .

RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001 && \
    chown -R nodejs:nodejs /app
USER nodejs

ENV PORT=3000
EXPOSE 3000

CMD [ "node", "app.js" ]
