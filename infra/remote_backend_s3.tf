terraform {
  backend "s3" {
    bucket = "my-terraform-state-bucket-samy-eu-central-1-app-rds"
    key    = "app-rds/terraform.tfstate"
    region = "eu-central-1"
  }
}