# ---- build stage ----
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# ---- runtime stage ----
FROM node:22-alpine
# git is required by the repository scanner (shallow clone of target repos)
RUN apk add --no-cache git
WORKDIR /app
ENV NODE_ENV=production
ENV QV_DB_PATH=/app/data/quantumvault.db
COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
COPY sample-target ./sample-target
# Run unprivileged: this process shallow-clones untrusted user-supplied repos,
# so it must never be root. The data dir is owned by the runtime user so the
# mounted volume is writable on first creation.
RUN mkdir -p /app/data && chown -R node:node /app
USER node
EXPOSE 4000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 \
  CMD node -e "fetch('http://localhost:4000/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "--experimental-sqlite", "dist/index.js"]
