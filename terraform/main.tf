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