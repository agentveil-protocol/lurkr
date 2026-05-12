FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python -m pip install --no-cache-dir .

RUN useradd --create-home --uid 1000 lurkr
USER lurkr

WORKDIR /workspace
ENTRYPOINT ["lurkr", "scan", "--path", "/workspace"]
CMD ["--output", "/workspace/lurkr-report.json"]
