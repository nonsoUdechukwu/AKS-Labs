variable "subscription_id" {
  type        = string
  description = "Subscription to deploy the lab into."
}

variable "location" {
  type    = string
  default = "westeurope"
}

variable "prefix" {
  type    = string
  default = "lab"

  validation {
    condition     = can(regex("^[a-z0-9]{2,10}$", var.prefix))
    error_message = "prefix must be 2-10 lowercase alphanumerics."
  }
}

variable "kubernetes_version" {
  type        = string
  default     = null
  description = "Null lets AKS pick the current default version."
}

variable "vm_size" {
  type    = string
  default = "Standard_D2ds_v5"
}

variable "safeguards_level" {
  type    = string
  default = "Warn"

  validation {
    condition     = contains(["Warn", "Enforce"], var.safeguards_level)
    error_message = "safeguards_level must be Warn or Enforce."
  }
}

variable "pss_level" {
  type    = string
  default = "Privileged"

  validation {
    condition     = contains(["Privileged", "Baseline", "Restricted"], var.pss_level)
    error_message = "pss_level must be Privileged, Baseline or Restricted."
  }
}

variable "excluded_namespaces" {
  type        = list(string)
  default     = ["lab-legacy"]
  description = "Namespaces that bypass both Deployment Safeguards and Pod Security Standards."

  validation {
    condition     = alltrue([for ns in var.excluded_namespaces : can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", ns))])
    error_message = "excluded_namespaces must be valid Kubernetes namespace names."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}
