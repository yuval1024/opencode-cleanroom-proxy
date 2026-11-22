# opencode for the clean-room repro, adapted from harness_k3/docker/Dockerfile.opencode-base (copied, not modified there).
# Network isolation is NOT done here: the container joins only the internal docker network cleanroom-int, and
# entrypoint.sh installs an OUTPUT firewall that allows only the filtering proxy, then drops every capability.
FROM node:22-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
      git ripgrep curl jq ca-certificates less procps python3 python3-pip python3-venv python3-dev \
      iptables util-linux build-essential \
  && rm -rf /var/lib/apt/lists/*
# Pinned: the newest release before the base commit's date (1.19.5, published 2026-10-28).
ARG OPENCODE_VERSION=1.19.5
RUN npm install -g "opencode-ai@${OPENCODE_VERSION}" && opencode --version
# uv in the image; its Python installs and cache live under /work so they persist across sessions (cycle 1-7 lost
# ~half of each session rebuilding /work/.venv because uv's Python lived in /tmp).
RUN pip install --break-system-packages -q "uv==0.9.5" && uv --version
# Trust the filtering proxy's CA everywhere (OpenSSL/curl/git/pip via the system bundle; Bun/Node via NODE_EXTRA_CA_CERTS).
COPY cleanroom-proxy-ca.crt /usr/local/share/ca-certificates/cleanroom-proxy-ca.crt
RUN update-ca-certificates
ENV NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/cleanroom-proxy-ca.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    PIP_CERT=/etc/ssl/certs/ca-certificates.crt \
    OPENCODE_CONFIG=/root/.config/opencode/opencode.json \
    UV_PYTHON_INSTALL_DIR=/work/.uv/python UV_CACHE_DIR=/work/.uv/cache UV_LINK_MODE=copy \
    XDG_CONFIG_HOME=/root/.config XDG_DATA_HOME=/root/.local/share \
    LANG=C.UTF-8 LC_ALL=C.UTF-8 NODE_OPTIONS=--max-old-space-size=4096 \
    OPENCODE_DISABLE_AUTOUPDATE=1 OPENCODE_DISABLE_MODELS_FETCH=1 OPENCODE_DISABLE_DEFAULT_PLUGINS=1 \
    OPENCODE_DISABLE_LSP_DOWNLOAD=1 OPENCODE_DISABLE_SHARE=1 OPENCODE_DISABLE_EXTERNAL_SKILLS=1 \
    OPENCODE_DISABLE_CLAUDE_CODE=1 OPENCODE_DISABLE_CHANNEL_DB=1 OPENCODE_ENABLE_EXA=1
RUN git config --global --add safe.directory '*' \
 && git config --global user.email "agent@example.local" && git config --global user.name "cleanroom agent"
RUN mkdir -p /root/.config/opencode /root/.local/share/opencode
COPY opencode.json /root/.config/opencode/opencode.json
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
WORKDIR /work/vllm
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["bash"]
