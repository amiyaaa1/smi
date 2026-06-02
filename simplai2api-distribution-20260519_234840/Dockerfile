FROM node:20-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Asia/Shanghai \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY requirements.txt ./
COPY third_party ./third_party
RUN python3 -m pip install --break-system-packages --no-cache-dir -r requirements.txt \
    && python3 -m playwright install --with-deps chromium

COPY . .

RUN mkdir -p /app/default-data /app/data /app/profiles /app/logs /app/cloakbrowser-cache \
    && cp -a /app/data/. /app/default-data/

EXPOSE 8031

CMD ["npx", "pm2-runtime", "start", "ecosystem.config.cjs"]
