output "resource_group" {
  value = azurerm_resource_group.lab.name
}

output "cluster_name" {
  value = azurerm_kubernetes_cluster.lab.name
}

output "get_credentials" {
  value = "az aks get-credentials -g ${azurerm_resource_group.lab.name} -n ${azurerm_kubernetes_cluster.lab.name} --overwrite-existing"
}

output "safeguards" {
  value = {
    level               = azurerm_kubernetes_cluster_deployment_safeguard.lab.level
    pss_level           = azurerm_kubernetes_cluster_deployment_safeguard.lab.pod_security_standards_level
    excluded_namespaces = azurerm_kubernetes_cluster_deployment_safeguard.lab.excluded_namespaces
  }
}
