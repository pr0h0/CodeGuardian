FROM ghcr.io/puppeteer/puppeteer:24.11.2

USER root
RUN apt-get update \
  && apt-get install -y --no-install-recommends ripgrep python3 python3-pip curl ca-certificates gnupg \
  && pip3 install --break-system-packages semgrep \
  && curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/master/install.sh | sh -s -- -b /usr/local/bin \
  && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
  && curl -sSfL https://raw.githubusercontent.com/google/osv-scanner/main/install.sh | sh -s -- -b /usr/local/bin || true \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json package-lock.json* tsconfig.json ./
RUN npm install
COPY . .
RUN npm run build

USER pptruser
ENTRYPOINT ["node", "/app/dist/src/index.js"]
