resource "aws_iam_policy" "eks_readonly_policy" {
  name        = "EKS-Dashboard-ReadOnly-Policy"
  description = "Allows read-only access to EKS for the central dashboard."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["eks:ListClusters", "eks:DescribeCluster", "eks:ListNodegroups", "eks:DescribeNodegroup"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role" "eks_readonly_role" {
  name = var.role_name

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = var.central_dashboard_principal_arn }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.eks_readonly_role.name
  policy_arn = aws_iam_policy.eks_readonly_policy.arn
}
