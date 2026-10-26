# Cloud Sandbox — status and setup

**Status: BLOCKED.** Phase 0 task 2 and part of task 3 are not complete. No
cloud account, credential, or CLI existed in this environment, and I will not
create a billable account on your behalf.

Everything that does not need the account is finished and verified:

| Piece | State |
| --- | --- |
| Container image for the target app | Built and run locally — `crisis-target-app:phase0` |
| App reachable over HTTP, all endpoints | Verified against the container on `127.0.0.1:8081` |
| Structured access log to stdout (what a managed platform ships to its log sink) | Verified via `docker logs` |
| Deploy script | Written: [deploy_target_app_gcp.sh](../infra/deploy_target_app_gcp.sh) — never executed |
| Real public URL | **Missing — needs the account** |

## Which cloud, and why

**Recommendation: GCP, Cloud Run.** Nothing is locked in; swap it if you have
AWS credits.

- Cloud Run takes the existing container image unchanged.
- The free tier covers an app at this traffic level.
- It hands back a real HTTPS URL, which is the exit criterion.
- stdout goes to Cloud Logging, which is a sane place for Phase 1's Detection
  system to read the access log from once the app is not local. The log file
  inside the container is ephemeral on Cloud Run — Detection must not depend
  on it.
- The rest of the stack (ADK, A2A) is Google's, so one account covers the
  model credentials too.

## What I need from you

1. A GCP account with billing enabled (the free tier still requires a billing
   account attached) and a **throwaway project** — this app is deliberately
   insecure and will be attacked in later phases. Keep it away from anything
   real.
2. `gcloud` CLI installed locally. It was not present:
   ```
   $ gcloud --version
   bash: gcloud: command not found
   ```
   Install: https://cloud.google.com/sdk/docs/install
3. Then, from the repo root:
   ```bash
   gcloud auth login
   gcloud config set project YOUR_PROJECT_ID
   gcloud auth list --filter=status:ACTIVE --format='value(account)'   # the task-2 access check

   export GCP_PROJECT_ID=YOUR_PROJECT_ID
   bash infra/deploy_target_app_gcp.sh
   ```
4. Paste the resulting URL into the table at the bottom of this file.

## Verifying once deployed

```bash
curl -s https://YOUR-URL/status

# a failed login -- the event Phase 1 Detection cares about
curl -s -X POST https://YOUR-URL/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"wrong"}'

# the full endpoint suite against the deployed instance
TARGET_APP_URL=https://YOUR-URL .venv-app/Scripts/python scripts/test_target_app.py

# confirm the access log lines arrived
gcloud logging read \
  'resource.type=cloud_run_revision AND resource.labels.service_name=crisis-target-app' \
  --limit 20 --format='value(textPayload)'
```

The `scripts/test_target_app.py` run skips its log-file assertions when
`TARGET_APP_URL` is set, because the deployed app's log is not on this
machine. The `gcloud logging read` above is how that half gets checked.

## If you prefer AWS

App Runner is the closest equivalent and takes the same image. The shape of
the work: push to ECR, `aws apprunner create-service` with port 8080, read the
log from CloudWatch instead of Cloud Logging. The task-2 access check becomes
`aws sts get-caller-identity`. Say the word and I will write the AWS script
instead — I did not write both, since the task says to pick one.

## Recorded deployment

| Field | Value |
| --- | --- |
| Cloud provider | *not yet chosen — GCP recommended* |
| Project / account id | *pending* |
| Region | `us-central1` (default in the script) |
| Service name | `crisis-target-app` |
| Public URL | *pending* |
| Deployed at | *pending* |
