FROM node:24-bookworm-slim
LABEL org.opencontainers.image.source="https://github.com/lilco-dev/lilauth"
WORKDIR /app
COPY --chown=node:node package.json ./
COPY --chown=node:node src/ ./src/
COPY --chown=node:node scripts/ ./scripts/
USER node
ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "src/main.mjs"]
