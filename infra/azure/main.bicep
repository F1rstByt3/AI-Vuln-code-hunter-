// =============================================================================
// AI Vuln Code Hunter — production infrastructure (provisions everything FRESH
// except the Azure AI Foundry deployment, which you already own).
//
// Provisions: Log Analytics, Container Apps env, API + worker + web container
// apps, Postgres Flexible Server, Storage (Blob), Azure Cache for Redis, Key
// Vault, Container Registry, and a user-assigned managed identity with the role
// assignments the apps need (Blob Data Contributor, Key Vault Secrets User,
// AcrPull).
//
// Foundry connection (endpoint / key / model) is set at runtime from the app's
// Settings UI, or seeded here into Key Vault via the foundryApiKey parameter.
//
//   az deployment group create -g <rg> -f main.bicep -p main.bicepparam
// =============================================================================

@description('Deployment region')
param location string = resourceGroup().location

@description('Short name prefix for resources')
param prefix string = 'vulnhunter'

@secure()
@description('Postgres admin password')
param pgAdminPassword string

@description('Container image for the API/worker (built & pushed by CI)')
param backendImage string = 'mcr.microsoft.com/k8se/quickstart:latest'

@description('Container image for the web frontend')
param webImage string = 'mcr.microsoft.com/k8se/quickstart:latest'

@description('Entra ID tenant id for auth')
param entraTenantId string = subscription().tenantId

@description('Entra ID API app (client) id')
param entraClientId string = ''

@secure()
@description('Optional: seed the Foundry API key into Key Vault')
param foundryApiKey string = ''

var suffix = uniqueString(resourceGroup().id)
var names = {
  identity: '${prefix}-id'
  logs: '${prefix}-logs'
  env: '${prefix}-cae'
  acr: '${prefix}acr${suffix}'
  storage: '${prefix}st${suffix}'
  kv: '${prefix}-kv-${take(suffix, 6)}'
  redis: '${prefix}-redis-${take(suffix, 6)}'
  pg: '${prefix}-pg-${take(suffix, 6)}'
}

// ---- Identity ---------------------------------------------------------------
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: names.identity
  location: location
}

// ---- Observability ----------------------------------------------------------
resource logs 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: names.logs
  location: location
  properties: { sku: { name: 'PerGB2018' }, retentionInDays: 30 }
}

// ---- Container registry ------------------------------------------------------
resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: names.acr
  location: location
  sku: { name: 'Standard' }
  properties: { adminUserEnabled: false }
}

// ---- Storage (Blob) ----------------------------------------------------------
resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: names.storage
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: { allowBlobPublicAccess: false, minimumTlsVersion: 'TLS1_2' }
  resource blob 'blobServices' = {
    name: 'default'
    resource container 'containers' = {
      name: 'hunter-artifacts'
    }
  }
}

// ---- Redis -------------------------------------------------------------------
resource redis 'Microsoft.Cache/redis@2023-08-01' = {
  name: names.redis
  location: location
  properties: {
    sku: { name: 'Basic', family: 'C', capacity: 1 }
    enableNonSslPort: false
    minimumTlsVersion: '1.2'
  }
}

// ---- Postgres ----------------------------------------------------------------
resource pg 'Microsoft.DBforPostgreSQL/flexibleServers@2023-06-01-preview' = {
  name: names.pg
  location: location
  sku: { name: 'Standard_D2ds_v5', tier: 'GeneralPurpose' }
  properties: {
    version: '16'
    administratorLogin: 'hunteradmin'
    administratorLoginPassword: pgAdminPassword
    storage: { storageSizeGB: 128 }
    highAvailability: { mode: 'Disabled' }
  }
  resource db 'databases' = {
    name: 'hunter'
  }
  // Dev convenience: allow Azure services. Tighten to VNet for production.
  resource fw 'firewallRules' = {
    name: 'AllowAzure'
    properties: { startIpAddress: '0.0.0.0', endIpAddress: '0.0.0.0' }
  }
}

// ---- Key Vault ---------------------------------------------------------------
resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: names.kv
  location: location
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: entraTenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
  }
  resource foundrySecret 'secrets' = if (!empty(foundryApiKey)) {
    name: 'foundry-api-key'
    properties: { value: foundryApiKey }
  }
}

// ---- Role assignments (managed identity) -------------------------------------
var roles = {
  blobContributor: 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
  kvSecretsUser: '4633458b-17de-408a-b874-0445c86b69e6'
  acrPull: '7f951dda-4ed3-4680-a7ca-43fe172d538d'
}

resource raBlob 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id, identity.id, roles.blobContributor)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.blobContributor)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource raKv 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(kv.id, identity.id, roles.kvSecretsUser)
  scope: kv
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.kvSecretsUser)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

resource raAcr 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, identity.id, roles.acrPull)
  scope: acr
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.acrPull)
    principalId: identity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

// ---- Container Apps environment ---------------------------------------------
resource env 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: names.env
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logs.properties.customerId
        sharedKey: logs.listKeys().primarySharedKey
      }
    }
  }
}

var dbUrl = 'postgresql+asyncpg://hunteradmin:${pgAdminPassword}@${pg.properties.fullyQualifiedDomainName}:5432/hunter'
var redisUrl = 'rediss://:${redis.listKeys().primaryKey}@${redis.properties.hostName}:6380/0'

var commonEnv = [
  { name: 'ENVIRONMENT', value: 'prod' }
  { name: 'DATABASE_URL', value: dbUrl }
  { name: 'REDIS_URL', value: redisUrl }
  { name: 'STORAGE_BACKEND', value: 'azure_blob' }
  { name: 'AZURE_STORAGE_ACCOUNT', value: storage.name }
  { name: 'AZURE_STORAGE_CONTAINER', value: 'hunter-artifacts' }
  { name: 'AZURE_CLIENT_ID', value: identity.properties.clientId }
  { name: 'AUTH_DISABLED', value: 'false' }
  { name: 'ENTRA_TENANT_ID', value: entraTenantId }
  { name: 'ENTRA_CLIENT_ID', value: entraClientId }
  { name: 'ENTRA_AUDIENCE', value: 'api://${entraClientId}' }
]

// ---- API container app -------------------------------------------------------
resource apiApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: '${prefix}-api'
  location: location
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${identity.id}': {} } }
  properties: {
    managedEnvironmentId: env.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: { external: true, targetPort: 8000, transport: 'auto' }
      registries: [ { server: '${acr.name}.azurecr.io', identity: identity.id } ]
    }
    template: {
      containers: [
        {
          name: 'api'
          image: backendImage
          resources: { cpu: 2, memory: '4Gi' }
          command: [ 'uvicorn', 'app.main:app', '--host', '0.0.0.0', '--port', '8000' ]
          env: commonEnv
        }
      ]
      scale: { minReplicas: 1, maxReplicas: 5 }
    }
  }
  dependsOn: [ raAcr ]
}

// ---- Worker container app (no ingress) --------------------------------------
resource workerApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: '${prefix}-worker'
  location: location
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${identity.id}': {} } }
  properties: {
    managedEnvironmentId: env.id
    configuration: {
      activeRevisionsMode: 'Single'
      registries: [ { server: '${acr.name}.azurecr.io', identity: identity.id } ]
    }
    template: {
      containers: [
        {
          name: 'worker'
          image: backendImage
          resources: { cpu: 4, memory: '8Gi' } // headroom for large-repo scans
          command: [ 'arq', 'app.worker.WorkerSettings' ]
          env: commonEnv
        }
      ]
      scale: { minReplicas: 1, maxReplicas: 10 }
    }
  }
  dependsOn: [ raAcr ]
}

// ---- Web (frontend) container app -------------------------------------------
resource webApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: '${prefix}-web'
  location: location
  identity: { type: 'UserAssigned', userAssignedIdentities: { '${identity.id}': {} } }
  properties: {
    managedEnvironmentId: env.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: { external: true, targetPort: 80, transport: 'auto' }
      registries: [ { server: '${acr.name}.azurecr.io', identity: identity.id } ]
    }
    template: {
      containers: [ { name: 'web', image: webImage, resources: { cpu: 1, memory: '2Gi' } } ]
      scale: { minReplicas: 1, maxReplicas: 3 }
    }
  }
  dependsOn: [ raAcr ]
}

output apiUrl string = 'https://${apiApp.properties.configuration.ingress.fqdn}'
output webUrl string = 'https://${webApp.properties.configuration.ingress.fqdn}'
output acrLoginServer string = '${acr.name}.azurecr.io'
output keyVaultName string = kv.name
