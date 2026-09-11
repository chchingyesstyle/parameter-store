FROM python:3.13-alpine

WORKDIR /app

RUN addgroup -S -g 1000 app \
    && adduser -S -D -u 1000 -G app app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app.py /app/app.py
RUN mkdir -p /app/data && chown -R app:app /app

USER app

ENV HOST=0.0.0.0 \
    PORT=8080 \
    DATA_DIR=/app/data \
    PYTHONUNBUFFERED=1

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2)"

ENTRYPOINT ["python", "/app/app.py"]
