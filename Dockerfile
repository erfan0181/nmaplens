FROM python:3.12-slim

WORKDIR /app

COPY nmaplens.py ./
COPY nmaplens_core ./nmaplens_core

ENTRYPOINT ["python3", "nmaplens.py"]
