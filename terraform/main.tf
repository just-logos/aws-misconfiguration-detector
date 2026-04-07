#########################
# Terraform Configuration
#########################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

########################
# Provider Configuration
########################

provider "aws" {
  region = var.aws_region
}

###########
# Random ID
###########

resource "random_id" "suffix" {
  byte_length = 4
}

#####
# VPC
#####

resource "aws_vpc" "default_vpc" {
  cidr_block = "10.0.0.0/16"
  tags = {
    Name = "default-vpc"
  }
}

############
# S3 Buckets
############
resource "aws_s3_bucket" "misconfigured_bucket" {
  bucket = "misconfigured-bucket-${random_id.suffix.hex}"
}

resource "aws_s3_bucket" "secure_bucket" {
  bucket = "secure-bucket-${random_id.suffix.hex}"
}

####################################
# S3 Bucket Encryption Configuration
####################################

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_encryption" {
  bucket = aws_s3_bucket.secure_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

#######################################
# S3 Bucket Public Access Configuration
#######################################

resource "aws_s3_bucket_public_access_block" "s3_public_access" {
  bucket                  = aws_s3_bucket.misconfigured_bucket.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_public_access_block" "s3_secure_access" {
  bucket                  = aws_s3_bucket.secure_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

##############
# IAM Policies
##############

resource "aws_iam_policy" "misconfigured_iam_policy" {
  name        = "misconfigured-iam-policy"
  path        = "/"
  description = "Misconfigured IAM Policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_policy" "secure_iam_policy" {
  name        = "secure-iam-policy"
  path        = "/"
  description = "Secure IAM Policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetObject",
        ]
        Effect   = "Allow"
        Resource = "arn:aws:s3:::secure-bucket-*"
      },
    ]
  })
}

#################
# Security Groups
#################

resource "aws_security_group" "misconfigured_sg" {
  name        = "misconfigured-sg"
  description = "Misconfigured Security Group"
  vpc_id      = aws_vpc.default_vpc.id
}

resource "aws_vpc_security_group_ingress_rule" "misconfigured_ingress_rules" {
  security_group_id = aws_security_group.misconfigured_sg.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 0
  ip_protocol       = "tcp"
  to_port           = 65535
}

resource "aws_security_group" "secure_sg" {
  name        = "secure-sg"
  description = "Secure Security Group"
  vpc_id      = aws_vpc.default_vpc.id
}

resource "aws_vpc_security_group_ingress_rule" "secure_ingress_rules" {
  security_group_id = aws_security_group.secure_sg.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  ip_protocol       = "tcp"
  to_port           = 443
}