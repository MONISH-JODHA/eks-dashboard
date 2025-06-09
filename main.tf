
resource "aws_iam_role" "dashboard_app_role" {
  name = "EKS-Dashboard-App-Role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "dashboard_assume_role_policy" {
  name = "EKS-Dashboard-AssumeRole-Policy"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = "sts:AssumeRole",
      Resource = var.target_account_role_arns
    }]
  })
}

resource "aws_iam_role_policy_attachment" "attach_assume_role" {
  role       = aws_iam_role.dashboard_app_role.name
  policy_arn = aws_iam_policy.dashboard_assume_role_policy.arn
}

resource "aws_iam_instance_profile" "dashboard_instance_profile" {
  name = "EKS-Dashboard-Instance-Profile"
  role = aws_iam_role.dashboard_app_role.name
}

resource "aws_security_group" "dashboard_sg" {
  name        = "eks-dashboard-sg"
  description = "Allow HTTP inbound traffic"
  
  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] 
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

resource "aws_instance" "dashboard_server" {
  ami           = data.aws_ami.amazon_linux_2.id
  instance_type = "t3.micro"
  
  iam_instance_profile = aws_iam_instance_profile.dashboard_instance_profile.name
  vpc_security_group_ids = [aws_security_group.dashboard_sg.id]

  user_data = <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y python3 git
              pip3 install virtualenv

              # Clone the repository
              cd /home/ec2-user
              git clone ${var.github_repo_url}
              cd eks-dashboard-flask-like # Change this if your repo has a different name

              # Set up Python environment and install dependencies
              python3 -m venv venv
              source venv/bin/activate
              pip install -r requirements.txt # Assumes you have a requirements.txt file

              # Set environment variables for the application
              export AWS_ASSUME_ROLES='${jsonencode(var.target_account_role_arns)}'
              export AWS_REGIONS="${var.aws_regions_to_scan}"
              
              # Run the application using uvicorn
              # Run as ec2-user in the background
              sudo -u ec2-user sh -c "source venv/bin/activate && uvicorn app:app --host 0.0.0.0 --port 8000 &"
              EOF

  tags = {
    Name = "EKS-Dashboard-Server"
  }
}

output "dashboard_url" {
  value = "http://${aws_instance.dashboard_server.public_ip}:8000"
}

output "central_dashboard_app_role_arn" {
  value = aws_iam_role.dashboard_app_role.arn
}
