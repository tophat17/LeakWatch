FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LEAKWATCH_DATA=/data \
    LEAKWATCH_PORT=8080

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Flat module layout — app/ contents land directly in /app so imports resolve.
COPY app/ /app/

EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=60s --timeout=5s --start-period=12s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=4)" || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
