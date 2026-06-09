# Self-contained image for the QuantumVault GitHub Action. Builds the CLI from
# the server package so the action has no external image/registry dependency.
FROM node:22-alpine
RUN apk add --no-cache git
WORKDIR /app
COPY server/package*.json ./
RUN npm ci
COPY server/tsconfig.json ./
COPY server/src ./src
RUN npm run build
COPY action-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
