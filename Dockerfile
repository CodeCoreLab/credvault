FROM python:3.12-slim

LABEL org.opencontainers.image.title="credvault" \
      org.opencontainers.image.description="AI-first credential platform: capability registry + envelope encryption + hash-chained audit"

ENV PYTHONUNBUFFERED=1 \
    CREDVAULT_HOME=/data \
    CREDVAULT_LISTEN_HOST=0.0.0.0 \
    CREDVAULT_LISTEN_PORT=8443

WORKDIR /app
COPY pyproject.toml README.md ./
COPY credvault ./credvault
COPY capabilities ./capabilities
COPY policy.yaml config.example.yaml ./
RUN pip install --no-cache-dir . && rm -rf /root/.cache

RUN useradd -r -u 10001 -m -d /home/credvault credvault \
 && mkdir -p /data && chown -R credvault:credvault /data
USER credvault
VOLUME ["/data"]
EXPOSE 8443

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8443/healthz',timeout=3).status==200 else 1)"

ENTRYPOINT ["credvault"]
CMD ["serve", "--mode", "web"]
