
output "read_only_role_arn" {
  description = "The ARN of the role created in this target account. Add this to the AWS_ASSUME_ROLES list in the central dashboard."
  value       = aws_iam_role.eks_readonly_role.arn
}