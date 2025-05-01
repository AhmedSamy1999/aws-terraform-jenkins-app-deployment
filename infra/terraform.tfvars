bucket_name = "my-terraform-state-bucket-samy-eu-central-1-app-rds"
name        = "environment"
environment = "dev-1"

vpc_cidr             = "10.0.0.0/16"
vpc_name             = "dev-proj-eu-central-vpc-1"
cidr_public_subnet   = ["10.0.1.0/24", "10.0.2.0/24"]
cidr_private_subnet  = ["10.0.3.0/24", "10.0.4.0/24"]
eu_availability_zone = ["eu-central-1a", "eu-central-1b"]

public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHwSg3kTQFUoKTk4C3kR8lNhCt9TCYQdhnB12CJXZbIU ahmed@DESKTOP-J8RD4LD"
ec2_ami_id     = "ami-03250b0e01c28d196"


ec2_user_data_install_app = ""

domain_name = "zyhosttest.online"
