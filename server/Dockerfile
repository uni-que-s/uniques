# ---- build stage ----
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
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
RUN npm install --omit=dev
COPY --from=build /app/dist ./dist
COPY sample-target ./sample-target
RUN mkdir -p /app/data
EXPOSE 4000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 \
  CMD node -e "fetch('http://localhost:4000/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "--experimental-sqlite", "dist/index.js"]
