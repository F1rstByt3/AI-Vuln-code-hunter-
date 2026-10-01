using './main.bicep'

param prefix = 'vulnhunter'
param pgAdminPassword = '<set-a-strong-password>'

// Container images — point these at your ACR after the first CI build/push.
// e.g. vulnhunteracr<suffix>.azurecr.io/backend:latest
param backendImage = 'mcr.microsoft.com/k8se/quickstart:latest'
param webImage = 'mcr.microsoft.com/k8se/quickstart:latest'

// Entra ID app registration for the API (see infra/azure/README.md).
param entraClientId = '<api-app-client-id>'

// Optional: seed the Foundry API key into Key Vault. You can also leave this
// blank and set the endpoint + key later from the app's Settings page.
param foundryApiKey = ''
