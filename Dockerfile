FROM python:3.12-slim

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

WORKDIR /app

# Install dependencies (cached layer — only re-runs when pyproject.toml or uv.lock change)
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Copy application source
COPY app.py sqlite_store.py ./
COPY users/ users/
COPY templates/ templates/

# Default user list — override at runtime with USERS_CSV or by mounting a volume
COPY users.csv ./

ENV USERS_CSV=users.csv

# Persist the RSA signing key and session database across container restarts
VOLUME /data

EXPOSE 5000

CMD ["uv", "run", "gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
