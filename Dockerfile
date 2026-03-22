FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app/backend

COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --upgrade pip && \
    pip install -r /tmp/requirements.txt

WORKDIR /app
COPY . /app

RUN mkdir -p /app/backend/storage/encrypted /app/backend/storage/quarantined

WORKDIR /app/backend
EXPOSE 8000

CMD ["sh", "-c", "python -m app.db.init_db && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
