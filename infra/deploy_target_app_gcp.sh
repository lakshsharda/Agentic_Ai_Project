#!/usr/bin/env bash
#
# Deploy the target ("victim") app to Google Cloud Run.
#
# NOT YET RUN -- this script is written and the image it deploys is built and
# verified locally, but no GCP project or credential existed in the Phase 0
# environment. See docs/CLOUD_SANDBOX.md for the one-time account setup.
#
# Usage, from the repo root:
#
#   export GCP_PROJECT_ID=your-project-id
#   bash infra/deploy_target_app_gcp.sh
#
# Cloud Run is the pick here because it takes the container image as-is, has a
# usable free tier, gives a real HTTPS URL, and ships stdout straight to Cloud
# Logging -- which is where Phase 1's Detection system will read the access log
# from once the app is no longer local.

set -euo pipefail

PROJECT_ID="${GCP_PROJECT_ID:?set GCP_PROJECT_ID to your sandbox project id}"
REGION="${GCP_REGION:-us-central1}"
SERVICE="${SERVICE_NAME:-crisis-target-app}"
REPO="${ARTIFACT_REPO:-crisis}"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPO}/${SERVICE}:phase0"

echo "==> project ${PROJECT_ID} / region ${REGION} / service ${SERVICE}"

echo "==> confirming CLI access"
gcloud auth list --filter=status:ACTIVE --format='value(account)'
gcloud config set project "${PROJECT_ID}"

echo "==> enabling the APIs this needs (idempotent)"
gcloud services enable \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com

echo "==> ensuring the Artifact Registry repo exists"
gcloud artifacts repositories describe "${REPO}" --location "${REGION}" >/dev/null 2>&1 || \
  gcloud artifacts repositories create "${REPO}" \
    --repository-format=docker \
    --location="${REGION}" \
    --description="Crisis Coordination Agents images"

echo "==> building and pushing ${IMAGE}"
gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet
docker build -f target_app/Dockerfile -t "${IMAGE}" .
docker push "${IMAGE}"

echo "==> deploying to Cloud Run"
# --allow-unauthenticated is required: the app has to be reachable for the
# Phase 2+ attack simulation to hit it. It is also why this belongs in a
# throwaway sandbox project and nowhere near anything real.
gcloud run deploy "${SERVICE}" \
  --image "${IMAGE}" \
  --region "${REGION}" \
  --platform managed \
  --allow-unauthenticated \
  --port 8080 \
  --cpu 1 \
  --memory 512Mi \
  --min-instances 0 \
  --max-instances 2 \
  --set-env-vars "TARGET_APP_LOG_DIR=/tmp/target_app_logs"

URL="$(gcloud run services describe "${SERVICE}" --region "${REGION}" --format='value(status.url)')"

echo
echo "==> deployed: ${URL}"
echo
echo "Verify it, from the repo root:"
echo "  curl -s ${URL}/status"
echo "  curl -s -X POST ${URL}/login -H 'Content-Type: application/json' \\"
echo "       -d '{\"username\":\"alice\",\"password\":\"wrong\"}'"
echo "  TARGET_APP_URL=${URL} .venv-app/Scripts/python scripts/test_target_app.py"
echo
echo "Then confirm the access log arrived in Cloud Logging:"
echo "  gcloud logging read \\"
echo "    'resource.type=cloud_run_revision AND resource.labels.service_name=${SERVICE}' \\"
echo "    --limit 20 --format='value(textPayload)'"
echo
echo "Record the URL in docs/CLOUD_SANDBOX.md so later phases can find it."
