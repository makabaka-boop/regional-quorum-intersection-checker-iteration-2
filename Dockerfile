FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY quorum/ /app/quorum/

EXPOSE 8080
USER nobody

CMD ["python", "-m", "quorum.server", "--host", "0.0.0.0", "--port", "8080"]
