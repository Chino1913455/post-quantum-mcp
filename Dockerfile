# Post-Quantum MCP — multi-stage build, runs as a hosted HTTP MCP server.
# syntax=docker/dockerfile:1

FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    MCP_TRANSPORT=http \
    PORT=3000
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY --from=build /app/dist ./dist
# Run as the unprivileged built-in node user.
USER node
EXPOSE 3000
# KEY_ENCRYPTION_SECRET must be provided at runtime if encrypted key storage is used.
CMD ["node", "dist/index.js"]
