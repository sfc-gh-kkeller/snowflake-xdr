FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

RUN useradd --uid 10001 --create-home xdr
USER 10001

EXPOSE 4318
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "4318", "--workers", "2", "--no-access-log"]
