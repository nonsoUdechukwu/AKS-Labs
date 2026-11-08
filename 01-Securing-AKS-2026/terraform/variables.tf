variable "subscription_id" {
  type        = string
  description = "Target subscription."
}

variable "location" {
  type    = string
  default = "westeurope"
}

variable "prefix" {
  type    = string
  default = "plat"
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "kubernetes_version" {
  type        = string
  description = "1.36+ gives GA user namespaces, fine-grained kubelet authz and MutatingAdmissionPolicy. 1.37+ adds platform-managed etcd encryption by default."
  default     = "1.37"
}

variable "admin_group_object_ids" {
  type        = list(string)
  description = "Entra groups that get cluster-admin through Azure RBAC. Keep this to a break-glass group; day-to-day access should use narrower Azure RBAC roles."
}

variable "api_server_authorized_ip_ranges" {
  type        = list(string)
  description = "CIDRs allowed to reach the public API server endpoint (CI runners, VPN egress). Leave empty only if you also make the cluster private."
  default     = []
}

variable "apps_os_sku" {
  type        = string
  description = "OS for the workload pool. AzureLinux3 and Ubuntu2404 are the documented user-namespace hosts. AzureContainerLinux (immutable /usr, SELinux enforcing, requires Trusted Launch) is set through azapi, so it is allowed here too."
  default     = "AzureLinux3"

  validation {
    condition     = contains(["AzureLinux3", "Ubuntu2404", "AzureContainerLinux"], var.apps_os_sku)
    error_message = "Use AzureLinux3, Ubuntu2404 or AzureContainerLinux."
  }
}

variable "system_vm_size" {
  type    = string
  default = "Standard_D4ds_v5"
}

variable "apps_vm_size" {
  type        = string
  description = "Must be a Gen2 size that supports Trusted Launch and encryption at host."
  default     = "Standard_D4ds_v5"
}

variable "enable_kms_cmk" {
  type        = bool
  description = "Use a customer-managed Key Vault key for etcd (KMS v2). Clusters on 1.37+ already get platform-managed encryption; turn this on when policy requires you to hold the key."
  default     = false
}

variable "safeguards_level" {
  type    = string
  default = "Enforce"

  validation {
    condition     = contains(["Warn", "Enforce"], var.safeguards_level)
    error_message = "Warn or Enforce."
  }
}

variable "safeguards_pss_level" {
  type    = string
  default = "Restricted"

  validation {
    condition     = contains(["Privileged", "Baseline", "Restricted"], var.safeguards_pss_level)
    error_message = "Privileged, Baseline or Restricted."
  }
}

variable "safeguards_excluded_namespaces" {
  type        = list(string)
  description = "Platform namespaces that legitimately need more than Restricted (CNI, CSI, security agents). Every entry here needs an owner and a review date."
  default     = ["platform-system"]
}

variable "tags" {
  type    = map(string)
  default = {}
}
