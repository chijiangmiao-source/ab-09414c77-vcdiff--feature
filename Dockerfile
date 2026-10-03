# Zero runtime dependencies: the base image alone can run the service.
FROM node:20-alpine

WORKDIR /app

# No npm install step is required (only node:* built-in modules are used).
COPY package.json ./
COPY src ./src
COPY static ./static
COPY scripts ./scripts
COPY test ./test
COPY fixtures ./fixtures

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8080

EXPOSE 8080

CMD ["node", "src/server.js"]
