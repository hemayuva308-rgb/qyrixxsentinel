# Base image pinned by immutable digest (python:3.12-slim, multi-arch index, 2026-11-02). Update deliberately:
# docker buildx imagetools inspect python:3.12-slim  -> new digest, then rebuild + rerun CI.
FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --uid 10001 --create-home qyrix && mkdir -p /data /srv/workspace /workspaces /witness && chown qyrix /data /srv/workspace /workspaces /witness
WORKDIR /srv
COPY requirements-lock.txt .
# fully pinned + hash-verified dependency set (supply-chain integrity); regenerate from requirements.txt
RUN pip install --no-cache-dir --require-hashes -r requirements-lock.txt
COPY app ./app
COPY migrations ./migrations
COPY workspace ./workspace
USER 10001
ENV QYRIX_CHAIN_FILE=/data/proof_chain.jsonl QYRIX_WORKSPACE=/srv/workspace
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
