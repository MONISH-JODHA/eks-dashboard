
variable "central_dashboard_principal_arn" {
  type        = string
  description = "The full ARN of the IAM role from the central account that will run the dashboard. Example: arn:aws:iam::999999999999:role/EKS-Dashboard-App-Role"
  validation {
    condition     = can(regex("^arn:aws:iam::[0-9]{12}:role/.+$", var.central_dashboard_principal_arn))
    error_message = "The provided value must be a valid IAM role ARN."
  }
}

variable "role_name" {
  type    = string
  default = "EKS-Dashboard-ReadOnly-Role"
}