variable "ami_id" {}
variable "instance_type" {}
variable "tag_name" {}
variable "public_key" {}
variable "subnet_id" {}
variable "sg_enable_ssh_https" {}
variable "enable_public_ip_address" {}
variable "user_data_install_app" {}
variable "ec2_sg_name_for_python_api" {}
variable "rds_endpoint" {}

output "ssh_connection_string_for_ec2" {
  value = format("%s%s", "ssh -i /Users/ahmed/.ssh/jenkins_demo ubuntu@", aws_instance.dev_proj_1_ec2.public_ip)
}

output "dev_proj_1_ec2_instance_id" {
  value = aws_instance.dev_proj_1_ec2.id
}

resource "aws_instance" "dev_proj_1_ec2" {
  ami           = var.ami_id
  instance_type = var.instance_type
  tags = {
    Name = var.tag_name
  }
  key_name                    = "aws_key"
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [var.sg_enable_ssh_https, var.ec2_sg_name_for_python_api]
  associate_public_ip_address = var.enable_public_ip_address

  user_data = var.user_data_install_app

  metadata_options {
    http_endpoint = "enabled"  # Enable the IMDSv2 endpoint [Allow metadata access from inside EC2]
    http_tokens   = "required" # Require the use of IMDSv2 tokens [	Force use of IMDSv2 (token-based access)]
  }
}

resource "aws_key_pair" "dev_proj_1_public_key" {
  key_name   = "aws_key"
  public_key = var.public_key
}