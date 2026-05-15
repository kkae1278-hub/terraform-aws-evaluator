# Fixture: well-configured resources that should produce 0 findings

resource "aws_instance" "web" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  monitoring = true

  root_block_device {
    encrypted = true
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "my-logs-bucket"
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_db_instance" "main" {
  identifier        = "main-db"
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  storage_encrypted   = true
  multi_az            = true
  deletion_protection = true
  backup_retention_period = 7

  performance_insights_enabled = true
  monitoring_interval          = 60

  password = var.db_password
}

resource "aws_security_group" "app" {
  name        = "app-sg"
  description = "Application security group"
  vpc_id      = aws_vpc.main.id
}

resource "aws_kms_key" "main" {
  description             = "Main encryption key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}
