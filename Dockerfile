FROM node:24-bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ffmpeg \
        curl \
        unzip \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# yt-dlp binary
RUN curl -fsSL https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp_linux \
        -o /usr/local/bin/yt-dlp && \
    chmod +x /usr/local/bin/yt-dlp

# Deno
RUN curl -fsSL https://deno.land/install.sh | DENO_INSTALL=/usr/local sh

# Downloads directory required by yt-dlp-mcp
RUN mkdir -p /root/Downloads
VOLUME /root/Downloads

# Pre-install MCP server and supergateway
RUN npm install -g @kevinwatt/yt-dlp-mcp@latest supergateway

EXPOSE 8000

CMD ["supergateway", \
     "--stdio", "yt-dlp-mcp", \
     "--outputTransport", "streamableHttp", \
     "--port", "8000", \
     "--cors", \
     "--healthEndpoint", "/healthz"]
