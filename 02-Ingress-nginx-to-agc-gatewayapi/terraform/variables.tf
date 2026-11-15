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
  type    = string
  default = "1.34"
}

variable "dns_zone_name" {
  type        = string
  description = "Public Azure DNS zone used for app hostnames and cert-manager DNS-01."
  default     = "contoso.example"
}

variable "acme_email" {
  type    = string
  default = "platform@contoso.example"
}

variable "gitops_repo_url" {
  type        = string
  description = "Git repository Flux reconciles from."
  default     = "https://github.com/contoso/aks-platform-gitops"
}

variable "gitops_branch" {
  type    = string
  default = "main"
}

variable "admin_allowed_cidrs" {
  type        = list(string)
  description = "Source ranges allowed to reach /admin. Replaces nginx.ingress.kubernetes.io/whitelist-source-range."
  default     = ["203.0.113.0/24"]
}

variable "waf_mode" {
  type        = string
  description = "Start in Detection during migration, flip to Prevention after a clean soak."
  default     = "Detection"
  validation {
    condition     = contains(["Detection", "Prevention"], var.waf_mode)
    error_message = "waf_mode must be Detection or Prevention."
  }
}

variable "frontends" {
  type        = list(string)
  description = "AGC frontends. Each has a stable FQDN that DNS CNAMEs to. Billed per frontend-hour."
  default     = ["fe-public"]
}

variable "tags" {
  type = map(string)
  default = {
    workload    = "aks-platform"
    cost-center = "platform"
  }
}

variable "ingress_monthly_budget" {
  type        = number
  description = "Monthly budget (USD) for the ingress resource group. Alerts at 80% actual and 100% forecast."
  default     = 400
}

variable "budget_contact_emails" {
  type    = list(string)
  default = ["platform@contoso.example"]
}
