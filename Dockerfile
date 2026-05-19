FROM node:20-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Asia/Shanghai \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

COPY simplai2api-distribution-20260519_234840/package.json simplai2api-distribution-20260519_234840/package-lock.json ./
RUN npm ci --omit=dev

COPY simplai2api-distribution-20260519_234840/requirements.txt ./
COPY simplai2api-distribution-20260519_234840/third_party ./third_party
RUN python3 -m pip install --break-system-packages --no-cache-dir -r requirements.txt \
    && python3 -m playwright install --with-deps chromium

COPY simplai2api-distribution-20260519_234840/ ./

RUN mkdir -p /app/data /app/profiles /app/logs /app/cloakbrowser-cache

EXPOSE 8031

CMD ["npx", "pm2-runtime", "start", "ecosystem.config.cjs"]
