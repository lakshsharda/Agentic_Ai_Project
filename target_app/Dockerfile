# Container image for the target ("victim") app.
#
# Built to run anywhere that takes a container: Cloud Run, App Runner, ECS, or
# plain `docker run`. The app listens on $PORT (8080 by default), which is what
# both Cloud Run and App Runner inject.

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    TARGET_APP_LOG_DIR=/var/log/target_app

WORKDIR /app

COPY requirements/target_app.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt gunicorn==23.0.0

COPY target_app/app.py ./target_app/app.py

RUN mkdir -p "$TARGET_APP_LOG_DIR"

EXPOSE 8080

# Two things to know about logging here:
#  * PYTHONUNBUFFERED keeps the stdout log line-by-line, which is what a
#    managed platform ships to its log sink.
#  * The file at TARGET_APP_LOG_DIR is ephemeral on Cloud Run / App Runner.
#    Phase 1's Detection system should read stdout (or the platform's log API)
#    when the app runs in the cloud, and the file only when it runs locally.
#
# Gunicorn's own access log is left off deliberately: the app already writes a
# structured access log, and gunicorn's would interleave a second, differently
# shaped line into the same stdout stream that Detection parses.
CMD exec gunicorn \
      --bind "0.0.0.0:${PORT}" \
      --workers 2 \
      --threads 4 \
      --timeout 30 \
      --chdir /app \
      target_app.app:app
