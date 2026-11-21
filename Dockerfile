FROM node:22-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates \
    && python3 -m venv /opt/venv \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY LICENSE UPSTREAM.md ./
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY requirements.txt ./
RUN /opt/venv/bin/pip install --no-cache-dir -r requirements.txt
COPY --chown=node:node src/ ./src/
COPY --chown=node:node web/ ./web/
RUN npm run build
ENV NODE_ENV=production \
    TOSUB2_PYTHON=/opt/venv/bin/python \
    ONBOARDING_OUTPUT_ROOT=/data \
    PYTHONDONTWRITEBYTECODE=1
USER node
EXPOSE 4399
CMD ["node", "src/console-server.mjs", "--host", "0.0.0.0", "--port", "4399"]
