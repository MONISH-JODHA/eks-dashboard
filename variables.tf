
variable "target_account_role_arns" {
  type        = list(string)
  description = "A list of the EKS-Dashboard-ReadOnly-Role ARNs from all target accounts."
  default     = []
}

variable "aws_regions_to_scan" {
  type        = string
  description = "Comma-separated string of AWS regions to scan for EKS clusters."
  default     = "us-east-1,us-west-2"
}

variable "github_repo_url" {
  type        = string
  description = "The HTTPS URL for your GitHub repo containing the dashboard code."
  # Example: "https://github.com/your-username/your-repo-name.git"
}