FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl unzip default-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# SonarScanner CLI (optional; only used when SONARQUBE_ENABLED=true). The Java
# runtime above is its only dependency. Pinned for reproducible builds. The
# download is best-effort: if the network blocks it the image still builds and
# SonarQube simply degrades (the worker logs the missing binary and continues).
ENV SONAR_SCANNER_VERSION=6.2.1.4610
RUN curl -sSLo /tmp/sonar-scanner.zip \
      "https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_SCANNER_VERSION}-linux-x64.zip" \
    && unzip -q /tmp/sonar-scanner.zip -d /opt \
    && mv "/opt/sonar-scanner-${SONAR_SCANNER_VERSION}-linux-x64" /opt/sonar-scanner \
    && ln -s /opt/sonar-scanner/bin/sonar-scanner /usr/local/bin/sonar-scanner \
    && rm /tmp/sonar-scanner.zip \
    || echo "WARN: sonar-scanner download failed; SonarQube scanning unavailable"

WORKDIR /app

# Copy only what pip needs for layer caching.
COPY pyproject.toml ./
# Create a minimal package so pip install "." resolves.
RUN mkdir -p app && echo '__version__ = "0.1.0"' > app/__init__.py && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir ".[dev]" semgrep && \
    rm -rf app/__init__.py

COPY . .

ENV PYTHONPATH=/app

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
