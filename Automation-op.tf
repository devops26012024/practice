variable "domain_name" {
  description = "Your domain name (e.g., example.com)"
  type        = string
}

variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs"
  type        = list(string)
}

variable "azure_client_id" {
  description = "Azure Entra ID App Client ID"
  type        = string
}

variable "azure_client_secret" {
  description = "Azure Entra ID App Client Secret"
  type        = string
  sensitive   = true
}

variable "azure_tenant_id" {
  description = "Azure Tenant ID"
  type        = string
}

main.tf

provider "aws" {
  region = var.aws_region
}

# Create a Route 53 Hosted Zone
resource "aws_route53_zone" "main" {
  name = var.domain_name
}

# Request an ACM Certificate for the domain
resource "aws_acm_certificate" "cert" {
  domain_name       = var.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

# ALB Security Group
resource "aws_security_group" "alb_sg" {
  name_prefix = "alb-sg-"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
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

# Create an Application Load Balancer (ALB)
resource "aws_lb" "alb" {
  name               = "my-app-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = var.subnet_ids
}

# Target Group for Backend EC2 instances
resource "aws_lb_target_group" "tg" {
  name     = "my-target-group"
  port     = 80
  protocol = "HTTP"
  vpc_id   = var.vpc_id
}

# ALB Listener (HTTPS with ACM & OIDC Auth)
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = aws_acm_certificate.cert.arn

  default_action {
    type = "authenticate-oidc"

    authenticate_oidc {
      authorization_endpoint = "https://login.microsoftonline.com/${var.azure_tenant_id}/oauth2/v2.0/authorize"
      token_endpoint         = "https://login.microsoftonline.com/${var.azure_tenant_id}/oauth2/v2.0/token"
      user_info_endpoint     = "https://graph.microsoft.com/oidc/userinfo"
      client_id              = var.azure_client_id
      client_secret          = var.azure_client_secret
      issuer                 = "https://login.microsoftonline.com/${var.azure_tenant_id}/v2.0"
      on_unauthenticated_request = "authenticate"
    }
  }

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
}

# Register EC2 Instance with Target Group
resource "aws_lb_target_group_attachment" "tg_attach" {
  target_group_arn = aws_lb_target_group.tg.arn
  target_id        = aws_instance.backend.id
  port            = 80
}

# Backend EC2 Instance
resource "aws_instance" "backend" {
  ami           = "ami-0c55b159cbfafe1f0"  # Amazon Linux 2 AMI
  instance_type = "t2.micro"
  subnet_id     = var.subnet_ids[0]
  security_groups = [aws_security_group.backend_sg.id]

  user_data = <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y httpd
              systemctl start httpd
              systemctl enable httpd
              echo "<h1>Welcome to the Secure App!</h1>" > /var/www/html/index.html
              EOF

  tags = {
    Name = "Backend-Instance"
  }
}

# Security Group for Backend EC2
resource "aws_security_group" "backend_sg" {
  vpc_id = var.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    security_groups = [aws_security_group.alb_sg.id]  # Allow traffic only from ALB
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

outputs.tf

output "alb_dns_name" {
  value = aws_lb.alb.dns_name
}

output "ec2_public_ip" {
  value = aws_instance.backend.public_ip
}
