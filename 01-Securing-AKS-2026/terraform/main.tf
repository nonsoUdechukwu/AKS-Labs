terraform {
  required_version = ">= 1.9"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.11"
    }
    azapi = {
      source  = "Azure/azapi"
      version = "~> 2.13"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

provider "azapi" {}

data "azurerm_client_config" "current" {}

locals {
  name = "${var.prefix}-${var.environment}"
  tags = merge(var.tags, { workload = "aks-platform", environment = var.environment, baseline = "aks-security-2026" })

  # AgentPool API version that has securityProfile.sshAccess, enableSecureBoot and enableVTPM
  # and accepts osSKU AzureContainerLinux. These are not exposed by azurerm 5.11.
  agentpool_api = "Microsoft.ContainerService/managedClusters/agentPools@2026-08-01"

  pool_security_profile = {
    enableSecureBoot = true
    enableVTPM       = true
    sshAccess        = "Disabled"
  }
}

resource "azurerm_resource_group" "aks" {
  name     = "rg-${local.name}-aks"
  location = var.location
  tags     = local.tags
}

# ---------------------------------------------------------------- network

resource "azurerm_virtual_network" "aks" {
  name                = "vnet-${local.name}-aks"
  location            = azurerm_resource_group.aks.location
  resource_group_name = azurerm_resource_group.aks.name
  address_space       = ["10.40.0.0/16"]
  tags                = local.tags
}

resource "azurerm_subnet" "nodes" {
  name                 = "snet-nodes"
  resource_group_name  = azurerm_resource_group.aks.name
  virtual_network_name = azurerm_virtual_network.aks.name
  address_prefixes     = ["10.40.0.0/22"]
}

# API server VNet integration: the control plane gets an internal LB in this subnet,
# so node-to-API-server traffic never leaves your VNet and no tunnel is needed.
resource "azurerm_subnet" "apiserver" {
  name                 = "snet-apiserver"
  resource_group_name  = azurerm_resource_group.aks.name
  virtual_network_name = azurerm_virtual_network.aks.name
  address_prefixes     = ["10.40.8.0/28"]

  delegation {
    name = "aks-apiserver"
    service_delegation {
      name    = "Microsoft.ContainerService/managedClusters"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

# ---------------------------------------------------------------- identity

resource "azurerm_user_assigned_identity" "control_plane" {
  name                = "id-${local.name}-aks-cp"
  location            = azurerm_resource_group.aks.location
  resource_group_name = azurerm_resource_group.aks.name
  tags                = local.tags
}

resource "azurerm_role_assignment" "cp_network" {
  scope                = azurerm_virtual_network.aks.id
  role_definition_name = "Network Contributor"
  principal_id         = azurerm_user_assigned_identity.control_plane.principal_id
}

# ---------------------------------------------------------------- etcd encryption (optional CMK)

resource "azurerm_key_vault" "kms" {
  count                         = var.enable_kms_cmk ? 1 : 0
  name                          = substr(replace("kv-${local.name}-kms", "-", ""), 0, 24)
  location                      = azurerm_resource_group.aks.location
  resource_group_name           = azurerm_resource_group.aks.name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "premium"
  rbac_authorization_enabled    = true
  purge_protection_enabled      = true
  soft_delete_retention_days    = 90
  public_network_access_enabled = true
  tags                          = local.tags
}

resource "azurerm_role_assignment" "kms_officer" {
  count                = var.enable_kms_cmk ? 1 : 0
  scope                = azurerm_key_vault.kms[0].id
  role_definition_name = "Key Vault Crypto Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_key_vault_key" "kms" {
  count        = var.enable_kms_cmk ? 1 : 0
  name         = "aks-etcd-kek"
  key_vault_id = azurerm_key_vault.kms[0].id
  key_type     = "RSA-HSM"
  key_size     = 2048
  key_opts     = ["encrypt", "decrypt", "wrapKey", "unwrapKey"]

  rotation_policy {
    automatic {
      time_before_expiry = "P30D"
    }
    expire_after         = "P1Y"
    notify_before_expiry = "P29D"
  }

  depends_on = [azurerm_role_assignment.kms_officer]
}

resource "azurerm_role_assignment" "kms_cp" {
  count                = var.enable_kms_cmk ? 1 : 0
  scope                = azurerm_key_vault.kms[0].id
  role_definition_name = "Key Vault Crypto User"
  principal_id         = azurerm_user_assigned_identity.control_plane.principal_id
}

# ---------------------------------------------------------------- detection

resource "azurerm_log_analytics_workspace" "sec" {
  name                = "log-${local.name}-aks-sec"
  location            = azurerm_resource_group.aks.location
  resource_group_name = azurerm_resource_group.aks.name
  sku                 = "PerGB2018"
  retention_in_days   = 90
  tags                = local.tags
}

# ---------------------------------------------------------------- cluster

resource "azurerm_kubernetes_cluster" "aks" {
  name                = "aks-${local.name}"
  location            = azurerm_resource_group.aks.location
  resource_group_name = azurerm_resource_group.aks.name
  dns_prefix          = "aks-${local.name}"
  kubernetes_version  = var.kubernetes_version
  sku_tier            = "Standard"
  tags                = local.tags

  # Identity layer: Entra-only, no static admin kubeconfig, no run-command backdoor.
  local_account_disabled = true
  run_command_enabled    = false
  azure_active_directory_role_based_access_control {
    azure_rbac_enabled     = true
    tenant_id              = data.azurerm_client_config.current.tenant_id
    admin_group_object_ids = var.admin_group_object_ids
  }
  oidc_issuer_enabled       = true
  workload_identity_enabled = true

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.control_plane.id]
  }

  api_server_access_profile {
    virtual_network_integration_enabled = true
    subnet_id                           = azurerm_subnet.apiserver.id
    authorized_ip_ranges                = var.api_server_authorized_ip_ranges
  }

  # Admission layer: Azure Policy add-on (now emits ValidatingAdmissionPolicies) is a
  # prerequisite for Deployment Safeguards below.
  azure_policy_enabled = true

  # Supply chain: remove unreferenced (often vulnerable) images from nodes.
  image_cleaner_enabled        = true
  image_cleaner_interval_hours = 48

  # Node layer: patch stream you own. NodeImage is the only node channel AzureContainerLinux supports.
  automatic_upgrade_channel = "patch"
  node_os_upgrade_channel   = "NodeImage"
  maintenance_window_node_os {
    frequency   = "Weekly"
    interval    = 1
    duration    = 4
    day_of_week = "Tuesday"
    start_time  = "02:00"
    utc_offset  = "+00:00"
  }

  network_profile {
    network_plugin      = "azure"
    network_plugin_mode = "overlay"
    network_data_plane  = "cilium"
    network_policy      = "cilium"
    outbound_type       = "loadBalancer"
    pod_cidr            = "192.168.0.0/16"
    service_cidr        = "10.41.0.0/16"
    dns_service_ip      = "10.41.0.10"

    # ACNS: FQDN and L7 network policies on top of Cilium.
    advanced_networking {
      security_enabled      = true
      observability_enabled = false
    }
  }

  dynamic "key_management_service" {
    for_each = var.enable_kms_cmk ? [1] : []
    content {
      key_vault_key_id         = azurerm_key_vault_key.kms[0].id
      key_vault_network_access = "Public"
    }
  }

  microsoft_defender {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.sec.id
  }

  # Explicit node pools (no Karpenter/NAP) so every pool's security profile is reviewable in code.
  node_provisioning_profile {
    mode = "Manual"
  }

  default_node_pool {
    name                         = "system"
    vm_size                      = var.system_vm_size
    node_count                   = 3
    zones                        = ["1", "2", "3"]
    os_sku                       = "AzureLinux3"
    host_encryption_enabled      = true
    only_critical_addons_enabled = true
    vnet_subnet_id               = azurerm_subnet.nodes.id
    temporary_name_for_rotation  = "systemtmp"

    upgrade_settings {
      max_surge                     = "33%"
      drain_timeout_in_minutes      = 30
      node_soak_duration_in_minutes = 0
    }
  }

  depends_on = [azurerm_role_assignment.cp_network, azurerm_role_assignment.kms_cp]
}

# Trusted Launch (Secure Boot + vTPM) and SSH disabled on the system pool.
# azurerm 5.11 doesn't model agentPool securityProfile, so patch it with azapi.
# Changing sshAccess or Trusted Launch reimages the pool: apply inside a maintenance window.
resource "azapi_update_resource" "system_pool_security" {
  type        = local.agentpool_api
  resource_id = "${azurerm_kubernetes_cluster.aks.id}/agentPools/system"
  body = {
    properties = {
      securityProfile = local.pool_security_profile
    }
  }
}

# Workload pool owned entirely by azapi so Trusted Launch, SSH-off and (optionally)
# Azure Container Linux are set at creation time, not patched in later.
resource "azapi_resource" "apps_pool" {
  type      = local.agentpool_api
  name      = "apps"
  parent_id = azurerm_kubernetes_cluster.aks.id

  # The API version may be newer than the schema bundled with the provider.
  schema_validation_enabled = false

  body = {
    properties = {
      mode                   = "User"
      osType                 = "Linux"
      osSKU                  = var.apps_os_sku
      vmSize                 = var.apps_vm_size
      orchestratorVersion    = var.kubernetes_version
      availabilityZones      = ["1", "2", "3"]
      enableAutoScaling      = true
      minCount               = 3
      maxCount               = 12
      enableEncryptionAtHost = true
      vnetSubnetID           = azurerm_subnet.nodes.id
      securityProfile        = local.pool_security_profile
      upgradeSettings = {
        maxSurge                  = "33%"
        drainTimeoutInMinutes     = 30
        nodeSoakDurationInMinutes = 0
      }
    }
  }

  depends_on = [azapi_update_resource.system_pool_security]
}

# Admission layer: Deployment Safeguards with Restricted Pod Security Standards.
# AKS Automatic ships Enforce + Baseline; Standard defaults to Privileged unless you set this.
resource "azurerm_kubernetes_cluster_deployment_safeguard" "this" {
  kubernetes_cluster_id        = azurerm_kubernetes_cluster.aks.id
  level                        = var.safeguards_level
  pod_security_standards_level = var.safeguards_pss_level
  excluded_namespaces          = var.safeguards_excluded_namespaces
}

# Detection: control-plane audit (admin and guard only, to keep ingestion cost sane).
resource "azurerm_monitor_diagnostic_setting" "aks_audit" {
  name                           = "aks-security-audit"
  target_resource_id             = azurerm_kubernetes_cluster.aks.id
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.sec.id
  log_analytics_destination_type = "Dedicated"

  enabled_log {
    category = "kube-audit-admin"
  }
  enabled_log {
    category = "guard"
  }
}
