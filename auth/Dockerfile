FROM node:22-bookworm-slim
WORKDIR /opt/login
COPY LICENSE UPSTREAM.md ./
COPY --chown=node:node auth/server.mjs ./
COPY --chown=node:node auth/public/ ./public/
ENV NODE_ENV=production
USER node
EXPOSE 4410
CMD ["node", "server.mjs"]
