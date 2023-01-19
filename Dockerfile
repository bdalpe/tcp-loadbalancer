FROM python:3.10-slim

WORKDIR /app

COPY src/ .

CMD python3 lb.py