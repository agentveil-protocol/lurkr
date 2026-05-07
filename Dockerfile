FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python -m pip install --no-cache-dir .

WORKDIR /workspace
ENTRYPOINT ["agentveil", "posture", "scan", "--path", "/workspace"]
CMD ["--output", "/workspace/agentveil-posture-report.json"]
