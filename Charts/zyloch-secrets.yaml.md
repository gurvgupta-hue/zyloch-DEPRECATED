# Secrets

- Find the YAML secrets in `173.224.122.95` at `/root/zyloch-charts/zyloch-secrets.yaml`.
- Update as necessary.
- Apply with:


  ```bash
  kubectl -n zyloch apply -f /root/zyloch-charts/zyloch-secrets.yaml
  ```

- Content

  ```yaml
  ---
  apiVersion: v1
  kind: Secret
  metadata:
    name: zyloch-mongodb-secrets
  type: Opaque
  stringData:
    MONGO_INITDB_ROOT_USERNAME: <REDACTED>
    MONGO_INITDB_ROOT_PASSWORD: <REDACTED>
  ---
  apiVersion: v1
  kind: Secret
  metadata:
    name: zyloch-backend-secrets
  type: Opaque
  stringData:
    MONGO_URI: <REDACTED>
    GITHUB_CLIENT_ID: <REDACTED>
    GITHUB_CLIENT_SECRET: <REDACTED>
    GITHUB_WEBHOOK_SECRET: <REDACTED>
    APP_JWT_SECRET: <REDACTED>
    APP_ENCRYPTION_SECRET: <REDACTED>
    GITHUB_APP_ID: <REDACTED>
    GITHUB_PRIVATE_KEY: |-
      <REDACTED>
  ---
  apiVersion: v1
  kind: Secret
  metadata:
    name: zyloch-policy-scanner-secrets
  type: Opaque
  stringData:
    MONGODB_URL: <REDACTED>
    GITHUB_WEBHOOK_SECRET: <REDACTED>
    GITHUB_APP_ID: <REDACTED>
    GITHUB_APP_PRIVATE_KEY: |-
      <REDACTED>

  ```
