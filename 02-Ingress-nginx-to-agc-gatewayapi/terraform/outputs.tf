output "agc_id" {
  value = azurerm_application_load_balancer.this.id
}

output "agc_frontend_fqdns" {
  description = "CNAME targets. Stable for the life of the frontend resource (BYO model)."
  value       = { for k, v in azurerm_application_load_balancer_frontend.this : k => v.fully_qualified_domain_name }
}

output "alb_controller_client_id" {
  value = azurerm_user_assigned_identity.alb.client_id
}

output "waf_policy_id" {
  value = azurerm_web_application_firewall_policy.this.id
}

output "log_analytics_workspace_id" {
  value = azurerm_log_analytics_workspace.this.id
}

output "get_credentials" {
  value = "az aks get-credentials -g ${azurerm_resource_group.aks.name} -n ${azurerm_kubernetes_cluster.this.name}"
}
