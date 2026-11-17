variable "display_name" {
  type        = string
  description = "Display name. Not an identifier - three objects in the test tenant shared one."
}

variable "owners" {
  type        = list(string)
  description = "Object IDs of accountable humans. At least one is REQUIRED."
}

variable "secret_lifetime_days" {
  type        = number
  default     = 90
  description = "Client secret lifetime in days. Capped by policy - see validation."
}

variable "allow_escalation_permissions" {
  type        = bool
  default     = false
  description = "Must be set deliberately to grant an escalation-class permission. Makes the grant a reviewed act rather than three clicks."
}

variable "required_resource_access" {
  type        = any
  default     = []
  description = "Explicit permission grants, so every one appears in a reviewable diff."
}
