FROM node:22-slim
LABEL org.opencontainers.image.title="Lyrie OSS-Scan Service"
LABEL org.opencontainers.image.source="https://github.com/OTT-Cybersecurity-LLC/lyrie-ai"

WORKDIR /app
COPY package.json bun.lock* ./
COPY packages/core/package.json ./packages/core/
COPY packages/core/src/ ./packages/core/src/

RUN npm install -g bun && bun install --production 2>/dev/null || npm install --production

EXPOSE 3020
ENV NODE_ENV=production
CMD ["node", "--input-type=module", "-e", "import('./packages/core/src/pentest/oss-scan/server.mjs')"]
