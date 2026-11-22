// Deployment Safeguards lab: AKS Standard cluster + Azure Policy add-on + safeguards.
// Deploy at resource-group scope:
//   az group create -n rg-lab-safeguards -l westeurope
//   az deployment group create -g rg-lab-safeguards -f main.bicep -p main.bicepparam
targetScope = 'resourceGroup'

@description('Azure region. Defaults to the resource group location.')
param location string = resourceGroup().location

@minLength(2)
@maxLength(10)
param prefix string = 'lab'

@description('Empty string lets AKS pick the current default version.')
param kubernetesVersion string = ''

param vmSize string = 'Standard_D2ds_v5'

@allowed(['Warn', 'Enforce'])
param safeguardsLevel string = 'Warn'

@allowed(['Privileged', 'Baseline', 'Restricted'])
param podSecurityStandardsLevel string = 'Privileged'

@description('Namespaces that bypass both Deployment Safeguards and Pod Security Standards.')
param excludedNamespaces array = ['lab-legacy']

param tags object = {}

var name = '${prefix}-safeguards'
var allTags = union(tags, { workload: 'aks-lab', lab: 'deployment-safeguards' })

resource aks 'Microsoft.ContainerService/managedClusters@2026-05-01' = {
  name: 'aks-${name}'
  location: location
  tags: allTags
  sku: {
    name: 'Base'
    tier: 'Free'
  }
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    dnsPrefix: 'aks-${name}'
    kubernetesVersion: empty(kubernetesVersion) ? null : kubernetesVersion
    enableRBAC: true
    // Prerequisite: Deployment Safeguards is delivered through the Azure Policy add-on.
    addonProfiles: {
      azurepolicy: {
        enabled: true
      }
    }
    oidcIssuerProfile: {
      enabled: true
    }
    securityProfile: {
      workloadIdentity: {
        enabled: true
      }
    }
    networkProfile: {
      networkPlugin: 'azure'
      networkPluginMode: 'overlay'
      networkDataplane: 'cilium'
      networkPolicy: 'cilium'
    }
    agentPoolProfiles: [
      {
        name: 'system'
        mode: 'System'
        count: 1
        vmSize: vmSize
        osType: 'Linux'
        osSKU: 'AzureLinux3'
        nodeTaints: ['CriticalAddonsOnly=true:NoSchedule']
      }
      {
        name: 'apps'
        mode: 'User'
        count: 2
        vmSize: vmSize
        osType: 'Linux'
        osSKU: 'AzureLinux3'
      }
    ]
  }
}

// Extension resource on the cluster. The name is always 'default'.
resource safeguards 'Microsoft.ContainerService/deploymentSafeguards@2025-07-01' = {
  name: 'default'
  scope: aks
  properties: {
    level: safeguardsLevel
    podSecurityStandardsLevel: podSecurityStandardsLevel
    excludedNamespaces: excludedNamespaces
  }
}

output clusterName string = aks.name
output getCredentials string = 'az aks get-credentials -g ${resourceGroup().name} -n ${aks.name} --overwrite-existing'
output systemExcludedNamespaces array = safeguards.properties.systemExcludedNamespaces
