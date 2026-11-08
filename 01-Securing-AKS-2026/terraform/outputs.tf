output "cluster_id" {
  value = azurerm_kubernetes_cluster.aks.id
}

output "cluster_name" {
  value = azurerm_kubernetes_cluster.aks.name
}

output "resource_group_name" {
  value = azurerm_resource_group.aks.name
}

output "oidc_issuer_url" {
  value = azurerm_kubernetes_cluster.aks.oidc_issuer_url
}

output "security_workspace_id" {
  value = azurerm_log_analytics_workspace.sec.id
}

output "posture_check" {
  description = "Run the posture script against the deployed cluster."
  value       = "python3 ../scripts/aks_posture.py -g ${azurerm_resource_group.aks.name} -n ${azurerm_kubernetes_cluster.aks.name}"
}
