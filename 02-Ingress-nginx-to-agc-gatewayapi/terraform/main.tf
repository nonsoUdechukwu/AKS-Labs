terraform {
  required_version = ">= 1.9"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.40"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

locals {
  name = "${var.prefix}-${var.environment}"
  tags = merge(var.tags, { environment = var.environment })

  # Built-in role definition IDs
  role_reader               = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
  role_agc_config_manager   = "fbc52c3f-28ad-4303-a892-8a056630b8f1" # AppGw for Containers Configuration Manager
  role_dns_zone_contributor = "befefa01-2a29-4197-83a8-272ff33ce314"
  role_network_contributor  = "4d97b98b-1d4f-4787-a291-c67834d212e7"
  alb_controller_namespace  = "azure-alb-system"
  alb_controller_sa         = "alb-controller-sa"
  cert_manager_namespace    = "cert-manager"
  cert_manager_sa           = "cert-manager"
  flux_config_namespace     = "cluster-config"
}

data "azurerm_client_config" "current" {}

# ---------------------------------------------------------------------------
# Resource groups: AGC lives in its own RG so the ALB controller's
# "Configuration Manager" role is scoped to ingress only, not the whole app RG.
# ---------------------------------------------------------------------------
resource "azurerm_resource_group" "aks" {
  name     = "rg-${local.name}-aks"
  location = var.location
  tags     = local.tags
}

resource "azurerm_resource_group" "ingress" {
  name     = "rg-${local.name}-ingress"
  location = var.location
  tags     = merge(local.tags, { cost-center = "platform-ingress" })
}

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------
resource "azurerm_virtual_network" "this" {
  name                = "vnet-${local.name}"
  location            = azurerm_resource_group.aks.location
  resource_group_name = azurerm_resource_group.aks.name
  address_space       = ["10.40.0.0/16"]
  tags                = local.tags
}

resource "azurerm_subnet" "nodes" {
  name                 = "snet-aks-nodes"
  resource_group_name  = azurerm_resource_group.aks.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = ["10.40.0.0/22"]
}

# AGC association subnet: /24 minimum, delegated, nothing else may live here.
resource "azurerm_subnet" "alb" {
  name                 = "snet-agc"
  resource_group_name  = azurerm_resource_group.aks.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = ["10.40.8.0/24"]

  delegation {
    name = "agc"
    service_delegation {
      name    = "Microsoft.ServiceNetworking/trafficControllers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

# ---------------------------------------------------------------------------
# Observability (also the FinOps showback source: AGCAccessLogs)
# ---------------------------------------------------------------------------
resource "azurerm_log_analytics_workspace" "this" {
  name                = "log-${local.name}"
  location            = azurerm_resource_group.aks.location
  resource_group_name = azurerm_resource_group.aks.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = local.tags
}

# ---------------------------------------------------------------------------
# AKS: Azure CNI Overlay (+ Cilium), OIDC issuer + workload identity are
# hard requirements for the ALB controller.
# ---------------------------------------------------------------------------
resource "azurerm_kubernetes_cluster" "this" {
  name                      = "aks-${local.name}"
  location                  = azurerm_resource_group.aks.location
  resource_group_name       = azurerm_resource_group.aks.name
  dns_prefix                = "aks-${local.name}"
  kubernetes_version        = var.kubernetes_version
  sku_tier                  = "Standard"
  oidc_issuer_enabled       = true
  workload_identity_enabled = true
  node_resource_group       = "rg-${local.name}-aks-nodes"

  default_node_pool {
    name                         = "system"
    vm_size                      = "Standard_D4ds_v5"
    vnet_subnet_id               = azurerm_subnet.nodes.id
    auto_scaling_enabled         = true
    min_count                    = 2
    max_count                    = 5
    zones                        = ["1", "2", "3"]
    only_critical_addons_enabled = false
    upgrade_settings {
      max_surge = "33%"
    }
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin      = "azure"
    network_plugin_mode = "overlay"
    network_data_plane  = "cilium"
    network_policy      = "cilium"
    pod_cidr            = "192.168.0.0/16"
    service_cidr        = "172.16.0.0/16"
    dns_service_ip      = "172.16.0.10"
  }

  oms_agent {
    log_analytics_workspace_id      = azurerm_log_analytics_workspace.this.id
    msi_auth_for_monitoring_enabled = true
  }

  tags = local.tags
}

# ---------------------------------------------------------------------------
# Application Gateway for Containers (BYO deployment model)
# Terraform owns the Azure lifecycle; Kubernetes only references it.
# Frontend FQDNs survive Gateway deletes/re-creates -> DNS stays stable.
# ---------------------------------------------------------------------------
resource "azurerm_application_load_balancer" "this" {
  name                = "agc-${local.name}"
  location            = azurerm_resource_group.ingress.location
  resource_group_name = azurerm_resource_group.ingress.name
  tags                = azurerm_resource_group.ingress.tags
}

resource "azurerm_application_load_balancer_frontend" "this" {
  for_each                     = toset(var.frontends)
  name                         = each.value
  application_load_balancer_id = azurerm_application_load_balancer.this.id
  tags                         = azurerm_resource_group.ingress.tags
}

# One association per AGC (current service limit) and it is the largest
# fixed line item on the bill. Do not create one per team.
resource "azurerm_application_load_balancer_subnet_association" "this" {
  name                         = "assoc-${local.name}"
  application_load_balancer_id = azurerm_application_load_balancer.this.id
  subnet_id                    = azurerm_subnet.alb.id
  tags                         = azurerm_resource_group.ingress.tags
}

resource "azurerm_monitor_diagnostic_setting" "agc" {
  name                           = "agc-to-law"
  target_resource_id             = azurerm_application_load_balancer.this.id
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.this.id
  log_analytics_destination_type = "Dedicated"

  enabled_log {
    category_group = "allLogs"
  }

  enabled_metric {
    category = "AllMetrics"
  }
}

# ---------------------------------------------------------------------------
# WAF: AGC supports DRS 2.1 only. IP allow-list for /admin replaces the
# nginx whitelist-source-range annotation.
# ---------------------------------------------------------------------------
resource "azurerm_web_application_firewall_policy" "this" {
  name                = "wafp-${local.name}-agc"
  location            = azurerm_resource_group.ingress.location
  resource_group_name = azurerm_resource_group.ingress.name
  tags                = azurerm_resource_group.ingress.tags

  policy_settings {
    enabled                     = true
    mode                        = var.waf_mode
    request_body_check          = true
    max_request_body_size_in_kb = 128
  }

  custom_rules {
    name      = "AdminAllowList"
    priority  = 10
    rule_type = "MatchRule"
    action    = "Block"

    match_conditions {
      match_variables {
        variable_name = "RequestUri"
      }
      operator           = "BeginsWith"
      match_values       = ["/admin"]
      transforms         = ["Lowercase"]
      negation_condition = false
    }

    match_conditions {
      match_variables {
        variable_name = "RemoteAddr"
      }
      operator           = "IPMatch"
      match_values       = var.admin_allowed_cidrs
      negation_condition = true
    }
  }

  managed_rules {
    managed_rule_set {
      type    = "Microsoft_DefaultRuleSet"
      version = "2.1"
    }
    managed_rule_set {
      type    = "Microsoft_BotManagerRuleSet"
      version = "1.1"
    }
  }
}

resource "azurerm_application_load_balancer_security_policy" "waf" {
  name                               = "secp-${local.name}-waf"
  application_load_balancer_id       = azurerm_application_load_balancer.this.id
  location                           = azurerm_resource_group.ingress.location
  web_application_firewall_policy_id = azurerm_web_application_firewall_policy.this.id
  tags                               = azurerm_resource_group.ingress.tags
}

# ---------------------------------------------------------------------------
# Identities (workload identity, no secrets)
# ---------------------------------------------------------------------------
resource "azurerm_user_assigned_identity" "alb" {
  name                = "id-${local.name}-alb-controller"
  location            = azurerm_resource_group.ingress.location
  resource_group_name = azurerm_resource_group.ingress.name
  tags                = local.tags
}

resource "azurerm_federated_identity_credential" "alb" {
  name                = "alb-controller"
  resource_group_name = azurerm_resource_group.ingress.name
  parent_id           = azurerm_user_assigned_identity.alb.id
  audience            = ["api://AzureADTokenExchange"]
  issuer              = azurerm_kubernetes_cluster.this.oidc_issuer_url
  subject             = "system:serviceaccount:${local.alb_controller_namespace}:${local.alb_controller_sa}"
}

# Reader on the node RG: the controller resolves pod/node networking.
resource "azurerm_role_assignment" "alb_reader_nodes" {
  scope              = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/resourceGroups/${azurerm_kubernetes_cluster.this.node_resource_group}"
  role_definition_id = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/${local.role_reader}"
  principal_id       = azurerm_user_assigned_identity.alb.principal_id
  principal_type     = "ServicePrincipal"
}

# Configuration Manager scoped to the dedicated ingress RG only.
resource "azurerm_role_assignment" "alb_config_manager" {
  scope              = azurerm_resource_group.ingress.id
  role_definition_id = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/${local.role_agc_config_manager}"
  principal_id       = azurerm_user_assigned_identity.alb.principal_id
  principal_type     = "ServicePrincipal"
}

# Microsoft's docs grant subnet join to the controller. In BYO, Terraform owns
# the association, but keep this so the controller can reconcile/repair it and
# so switching to ALB-managed mode later does not need an RBAC change.
resource "azurerm_role_assignment" "alb_subnet" {
  scope              = azurerm_subnet.alb.id
  role_definition_id = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/${local.role_network_contributor}"
  principal_id       = azurerm_user_assigned_identity.alb.principal_id
  principal_type     = "ServicePrincipal"
}

resource "azurerm_dns_zone" "this" {
  name                = var.dns_zone_name
  resource_group_name = azurerm_resource_group.ingress.name
  tags                = local.tags
}

resource "azurerm_user_assigned_identity" "cert_manager" {
  name                = "id-${local.name}-cert-manager"
  location            = azurerm_resource_group.ingress.location
  resource_group_name = azurerm_resource_group.ingress.name
  tags                = local.tags
}

resource "azurerm_federated_identity_credential" "cert_manager" {
  name                = "cert-manager"
  resource_group_name = azurerm_resource_group.ingress.name
  parent_id           = azurerm_user_assigned_identity.cert_manager.id
  audience            = ["api://AzureADTokenExchange"]
  issuer              = azurerm_kubernetes_cluster.this.oidc_issuer_url
  subject             = "system:serviceaccount:${local.cert_manager_namespace}:${local.cert_manager_sa}"
}

resource "azurerm_role_assignment" "cert_manager_dns" {
  scope              = azurerm_dns_zone.this.id
  role_definition_id = "/subscriptions/${data.azurerm_client_config.current.subscription_id}/providers/Microsoft.Authorization/roleDefinitions/${local.role_dns_zone_contributor}"
  principal_id       = azurerm_user_assigned_identity.cert_manager.principal_id
  principal_type     = "ServicePrincipal"
}

# App hostnames CNAME to the AGC frontend FQDN. Keep TTL low during cutover.
resource "azurerm_dns_cname_record" "shop" {
  name                = "shop"
  zone_name           = azurerm_dns_zone.this.name
  resource_group_name = azurerm_resource_group.ingress.name
  ttl                 = 60
  record              = azurerm_application_load_balancer_frontend.this[var.frontends[0]].fully_qualified_domain_name
  tags                = local.tags
}

# ---------------------------------------------------------------------------
# GitOps: Flux extension + configuration. Terraform hands environment
# specific IDs to Flux via post_build substitution, so Git holds no
# subscription IDs, client IDs or secrets.
# ---------------------------------------------------------------------------
resource "azurerm_kubernetes_cluster_extension" "flux" {
  name           = "flux"
  cluster_id     = azurerm_kubernetes_cluster.this.id
  extension_type = "microsoft.flux"
}

locals {
  flux_substitutions = {
    ALB_ID                  = azurerm_application_load_balancer.this.id
    ALB_FRONTEND            = var.frontends[0]
    ALB_CLIENT_ID           = azurerm_user_assigned_identity.alb.client_id
    WAF_POLICY_ID           = azurerm_web_application_firewall_policy.this.id
    CERT_MANAGER_CLIENT_ID  = azurerm_user_assigned_identity.cert_manager.client_id
    DNS_ZONE                = azurerm_dns_zone.this.name
    DNS_ZONE_RESOURCE_GROUP = azurerm_resource_group.ingress.name
    AZURE_SUBSCRIPTION_ID   = data.azurerm_client_config.current.subscription_id
    ACME_EMAIL              = var.acme_email
  }
}

resource "azurerm_kubernetes_flux_configuration" "platform" {
  name       = "platform"
  cluster_id = azurerm_kubernetes_cluster.this.id
  namespace  = local.flux_config_namespace
  scope      = "cluster"

  git_repository {
    url             = var.gitops_repo_url
    reference_type  = "branch"
    reference_value = var.gitops_branch
  }

  kustomizations {
    name                       = "infra-controllers"
    path                       = "./gitops/infrastructure/controllers"
    sync_interval_in_seconds   = 300
    retry_interval_in_seconds  = 60
    timeout_in_seconds         = 900
    wait                       = true
    garbage_collection_enabled = true
    post_build {
      substitute = local.flux_substitutions
    }
  }

  kustomizations {
    name                       = "infra-configs"
    path                       = "./gitops/infrastructure/configs"
    depends_on                 = ["infra-controllers"]
    sync_interval_in_seconds   = 300
    retry_interval_in_seconds  = 60
    garbage_collection_enabled = true
    post_build {
      substitute = local.flux_substitutions
    }
  }

  kustomizations {
    name                       = "apps"
    path                       = "./gitops/apps"
    depends_on                 = ["infra-configs"]
    sync_interval_in_seconds   = 120
    retry_interval_in_seconds  = 60
    garbage_collection_enabled = true
    post_build {
      substitute = local.flux_substitutions
    }
  }

  depends_on = [
    azurerm_kubernetes_cluster_extension.flux,
    azurerm_federated_identity_credential.alb,
    azurerm_federated_identity_credential.cert_manager,
    azurerm_application_load_balancer_subnet_association.this,
  ]
}

# ---------------------------------------------------------------------------
# FinOps guardrail: the dedicated ingress RG makes the edge bill a single,
# budgetable line. Forecast alerts catch a runaway CU bill (or someone creating
# a second association) before month end.
# ---------------------------------------------------------------------------
resource "azurerm_consumption_budget_resource_group" "ingress" {
  name              = "budget-${local.name}-ingress"
  resource_group_id = azurerm_resource_group.ingress.id
  amount            = var.ingress_monthly_budget
  time_grain        = "Monthly"

  time_period {
    start_date = "2026-11-01T00:00:00Z"
  }

  notification {
    enabled        = true
    threshold      = 80
    operator       = "GreaterThanOrEqualTo"
    threshold_type = "Actual"
    contact_emails = var.budget_contact_emails
  }

  notification {
    enabled        = true
    threshold      = 100
    operator       = "GreaterThanOrEqualTo"
    threshold_type = "Forecasted"
    contact_emails = var.budget_contact_emails
  }

  lifecycle {
    ignore_changes = [time_period]
  }
}
