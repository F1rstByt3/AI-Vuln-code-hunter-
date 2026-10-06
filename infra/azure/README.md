# Azure deployment (production)

This Bicep provisions **everything fresh except your Azure AI Foundry deployment**:

| Resource | Purpose |
|---|---|
| Container Apps environment | hosts `api`, `worker`, `web` |
| Postgres Flexible Server | clients/projects/scans/findings |
| Storage account (Blob) | uploaded code + artifacts |
| Azure Cache for Redis | job queue + live SSE event streams |
| Key Vault | secrets (incl. optional Foundry key) |
| Container Registry | your built images |
| User-assigned managed identity | Blob Data Contributor, KV Secrets User, AcrPull |

The Foundry **endpoint, key, and model are set at runtime** from the app's
Settings page (or seed the key via the `foundryApiKey` param → Key Vault).

## 1. Build & push images

```bash
RG=vuln-hunter-rg
az group create -n $RG -l uksouth

# Provision once with placeholder images to create the ACR, then push:
ACR=$(az deployment group create -g $RG -f main.bicep -p main.bicepparam \
  --query properties.outputs.acrLoginServer.value -o tsv)

az acr login -n ${ACR%%.*}
docker build -t $ACR/backend:latest ../../backend
docker build -t $ACR/web:latest --build-arg VITE_API_BASE_URL=/ ../../frontend
docker push $ACR/backend:latest && docker push $ACR/web:latest
```

## 2. Deploy with real images

Update `backendImage` / `webImage` in `main.bicepparam` to the `$ACR/...` refs, then:

```bash
az deployment group create -g $RG -f main.bicep -p main.bicepparam
```

Outputs include `apiUrl` and `webUrl`.

## 3. Entra ID (auth)

1. Register an **API app** (exposes `api://<client-id>`), add an app role `admin`.
2. Register a **SPA app** for the frontend; grant it the API scope.
3. Put the API app's client id in `entraClientId`.
4. Wire MSAL into `frontend/src/lib/api.ts` (`authHeader()` returns the access token).

Until then, set `AUTH_DISABLED=true` to demo without an IdP.

## Notes / hardening for production

- Swap the Postgres `AllowAzure` firewall rule for **VNet integration + private endpoints** on Postgres, Storage, Redis, and Key Vault.
- Run scan workers on a dedicated, **network-egress-restricted** profile — they execute static analysis over untrusted code (never the code itself).
- For 10GB+ uploads, prefer **direct-to-Blob SAS** uploads from the browser to bypass the API entirely (the chunked API path also works).
- Replace the dev `init_models()` table creation with **Alembic migrations** before going live.
