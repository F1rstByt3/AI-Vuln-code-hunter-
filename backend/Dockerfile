FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only what pip needs for layer caching.
COPY pyproject.toml ./
# Create a minimal package so pip install "." resolves.
RUN mkdir -p app && echo '__version__ = "0.1.0"' > app/__init__.py && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir ".[dev]" semgrep && \
    rm -rf app/__init__.py

COPY . .

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
