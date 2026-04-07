# Multi-stage: copy only the docker binary from official image
FROM docker:29-cli AS docker-cli

FROM python:3.12-slim

COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker

WORKDIR /app
COPY app.py .

ENV PYTHONUNBUFFERED=1

CMD ["python3", "app.py"]
