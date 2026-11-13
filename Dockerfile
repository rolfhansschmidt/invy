FROM ghcr.io/astral-sh/uv:latest AS uv
FROM python:3.13-alpine
COPY --from=uv /uv /usr/local/bin/uv
RUN apk upgrade --no-cache
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 PORT=8000 INVENTORY_FILE=/data/inventory.ods
COPY requirements.txt ./
RUN uv pip install --system --no-cache -r requirements.txt \
    && uv pip uninstall --system pip \
    && rm -rf /usr/local/lib/python3.13/ensurepip \
    && rm /usr/local/bin/uv
COPY --chown=1000:1000 server.py web.py storage.py security_state.py ./
COPY --chown=1000:1000 static/ ./static/
RUN mkdir /data && chown 1000:1000 /data
USER 1000:1000
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).read()"]
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "8", "--timeout", "60", "--no-control-socket", "web:create_app()"]
