FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CONFIGMASK_DB_PATH=/data/configmask.db \
    CONFIGMASK_PORT=8741

RUN useradd --system --uid 10001 --create-home --home-dir /home/configmask configmask \
    && mkdir -p /data /app \
    && chown configmask:configmask /data

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY samples ./samples
COPY README.md ./README.md
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

EXPOSE 8741
VOLUME ["/data"]

ENTRYPOINT ["/entrypoint.sh"]
