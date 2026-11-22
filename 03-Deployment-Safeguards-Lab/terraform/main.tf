terraform {
  required_version = ">= 1.9"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.11"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

locals {
  name = "${var.prefix}-safeguards"
  tags = merge(var.tags, { workload = "aks-lab", lab = "deployment-safeguards" })
}

resource "azurerm_resource_group" "lab" {
  name     = "rg-${local.name}"
  location = var.location
  tags     = local.tags
}

# Small, disposable AKS Standard cluster. Deployment Safeguards needs nothing more than
# the Azure Policy add-on, so everything else is kept deliberately boring and cheap.
resource "azurerm_kubernetes_cluster" "lab" {
  name                = "aks-${local.name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  dns_prefix          = "aks-${local.name}"
  kubernetes_version  = var.kubernetes_version
  sku_tier            = "Free"
  tags                = local.tags

  # Prerequisite: Deployment Safeguards is delivered through the Azure Policy add-on.
  azure_policy_enabled = true

  oidc_issuer_enabled       = true
  workload_identity_enabled = true

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin      = "azure"
    network_plugin_mode = "overlay"
    network_data_plane  = "cilium"
    network_policy      = "cilium"
  }

  node_provisioning_profile {
    mode = "Manual"
  }

  # System pool carries CriticalAddonsOnly so lab workloads land on the user pool.
  default_node_pool {
    name                         = "system"
    vm_size                      = var.vm_size
    node_count                   = 1
    os_sku                       = "AzureLinux3"
    only_critical_addons_enabled = true
    temporary_name_for_rotation  = "systemtmp"

    upgrade_settings {
      max_surge = "10%"
    }
  }
}

# Two user nodes so the anti-affinity and topology spread mutations have somewhere to spread.
resource "azurerm_kubernetes_cluster_node_pool" "apps" {
  name                  = "apps"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.lab.id
  vm_size               = var.vm_size
  node_count            = 2
  os_sku                = "AzureLinux3"
  mode                  = "User"
  tags                  = local.tags

  upgrade_settings {
    max_surge = "10%"
  }
}

# The subject of the lab. Flip level / PSS level / exclusions in tfvars and re-apply
# between scenario runs. This is an in-place update; no cluster or pool is replaced.
resource "azurerm_kubernetes_cluster_deployment_safeguard" "lab" {
  kubernetes_cluster_id        = azurerm_kubernetes_cluster.lab.id
  level                        = var.safeguards_level
  pod_security_standards_level = var.pss_level
  excluded_namespaces          = var.excluded_namespaces

  depends_on = [azurerm_kubernetes_cluster_node_pool.apps]
}
