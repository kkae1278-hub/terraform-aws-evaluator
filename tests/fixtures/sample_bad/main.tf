# Fixture: intentionally misconfigured resources that should trigger findings

resource "aws_instance" "bad" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"

  # No metadata_options -> IMDSv1 allowed (EC2-001 HIGH)
  # No monitoring -> EC2-002 LOW
  # No encrypted root block -> EC2-003 MEDIUM

  associate_public_ip_address = true  # EC2-007 MEDIUM
}

resource "aws_s3_bucket" "public" {
  bucket = "my-public-bucket"
  # No versioning, no encryption, no public access block -> multiple findings
}

resource "aws_db_instance" "insecure" {
  identifier        = "insecure-db"
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  storage_encrypted       = false    # RDS-001 HIGH
  multi_az                = false    # RDS-002 MEDIUM
  deletion_protection     = false    # RDS-006 HIGH
  backup_retention_period = 0        # RDS-009 MEDIUM

  password = "hardcoded-password"    # RDS-010 CRITICAL
}

resource "aws_security_group" "open" {
  name        = "open-sg"
  description = "Dangerously open security group"
  vpc_id      = "vpc-12345"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # SG-001 CRITICAL
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # SG-001 CRITICAL
  }
}

resource "aws_iam_role_policy" "admin" {
  name = "admin-policy"
  role = "some-role"

  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["*"]
      Resource = "*"
    }]
  })
  # IAM-001 CRITICAL: wildcard action
}

resource "aws_kms_key" "no_rotation" {
  description             = "Key without rotation"
  enable_key_rotation     = false  # KMS-001 MEDIUM
  deletion_window_in_days = 7
}
