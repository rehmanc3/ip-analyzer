#!/usr/bin/env python3
"""
Terraform Infrastructure Generator for IP Analysis Utility
"""

import argparse
from pathlib import Path


class TerraformGenerator:
    def __init__(self, output_dir: str = "terraform"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

    def generate_main_tf(self) -> str:
        return """terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}
"""

    def generate_aws_tf(self) -> str:
        return """# AWS Data Sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

# VPC
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "ip-analysis-vpc"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "ip-analysis-igw"
  }
}

# Public Subnet
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "ip-analysis-public-subnet"
  }
}

# Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "ip-analysis-public-rt"
  }
}

# Route Table Association
resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Security Group
resource "aws_security_group" "ip_analysis" {
  name        = "ip-analysis-sg"
  description = "Security group for IP analysis server"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "ip-analysis-sg"
  }
}

# EC2 Instance
resource "aws_instance" "ip_analysis" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.aws_instance_type
  key_name              = var.aws_key_name
  subnet_id             = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.ip_analysis.id]

  user_data = <<-EOF
    #!/bin/bash
    apt-get update
    apt-get install -y python3 python3-pip git
    pip3 install requests

    useradd -m -s /bin/bash ipanalysis
    mkdir -p /home/ipanalysis/ip-analysis-utility
    chown -R ipanalysis:ipanalysis /home/ipanalysis
  EOF

  tags = {
    Name = "ip-analysis-server"
  }
}
"""

    def generate_gcp_tf(self) -> str:
        return """# GCP Network
resource "google_compute_network" "main" {
  name                    = "ip-analysis-network"
  auto_create_subnetworks = false
}

# GCP Subnet
resource "google_compute_subnetwork" "main" {
  name          = "ip-analysis-subnet"
  ip_cidr_range = "10.1.0.0/24"
  region        = var.gcp_region
  network       = google_compute_network.main.id
}

# GCP Firewall
resource "google_compute_firewall" "allow_ssh_http" {
  name    = "ip-analysis-firewall"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["22", "80"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["ip-analysis"]
}

# GCP Compute Instance
resource "google_compute_instance" "ip_analysis" {
  name         = "ip-analysis-server"
  machine_type = var.gcp_machine_type
  zone         = var.gcp_zone

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
      size  = 20
    }
  }

  network_interface {
    network    = google_compute_network.main.id
    subnetwork = google_compute_subnetwork.main.id

    access_config {
      # Ephemeral external IP
    }
  }

  metadata_startup_script = <<-EOF
    #!/bin/bash
    apt-get update
    apt-get install -y python3 python3-pip git
    pip3 install requests

    useradd -m -s /bin/bash ipanalysis
    mkdir -p /home/ipanalysis/ip-analysis-utility
    chown -R ipanalysis:ipanalysis /home/ipanalysis
  EOF

  tags = ["ip-analysis"]
}
"""

    def generate_variables_tf(self) -> str:
        return """variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "aws_instance_type" {
  description = "AWS EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "aws_key_name" {
  description = "AWS key pair name"
  type        = string
}

variable "gcp_project_id" {
  description = "GCP project ID"
  type        = string
}

variable "gcp_region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "gcp_zone" {
  description = "GCP zone"
  type        = string
  default     = "us-central1-a"
}

variable "gcp_machine_type" {
  description = "GCP machine type"
  type        = string
  default     = "e2-micro"
}
"""

    def generate_outputs_tf(self) -> str:
        return """output "aws_instance_ip" {
  description = "AWS instance public IP"
  value       = aws_instance.ip_analysis.public_ip
}

output "gcp_instance_ip" {
  description = "GCP instance external IP"
  value       = google_compute_instance.ip_analysis.network_interface[0].access_config[0].nat_ip
}

output "connection_info" {
  description = "SSH connection commands"
  value = {
    aws = "ssh -i ${var.aws_key_name}.pem ubuntu@${aws_instance.ip_analysis.public_ip}"
    gcp = "gcloud compute ssh ip-analysis-server --zone=${var.gcp_zone}"
  }
}
"""

    def generate_tfvars_example(self) -> str:
        return """# AWS Configuration
aws_region        = "us-east-1"
aws_instance_type = "t3.micro"
aws_key_name      = "your-key-pair-name"

# GCP Configuration
gcp_project_id   = "your-gcp-project-id"
gcp_region       = "us-central1"
gcp_zone         = "us-central1-a"
gcp_machine_type = "e2-micro"
"""

    def generate_all_files(self):
        files = {
            'main.tf': self.generate_main_tf(),
            'aws.tf': self.generate_aws_tf(),
            'gcp.tf': self.generate_gcp_tf(),
            'variables.tf': self.generate_variables_tf(),
            'outputs.tf': self.generate_outputs_tf(),
            'terraform.tfvars.example': self.generate_tfvars_example()
        }

        for filename, content in files.items():
            filepath = self.output_dir / filename
            with open(filepath, 'w') as f:
                f.write(content)
            print(f"Generated: {filepath}")

        print(f"\nTerraform files generated in: {self.output_dir}")


def main():
    parser = argparse.ArgumentParser(description="Generate Terraform infrastructure")
    parser.add_argument('--output-dir', default='terraform', help='Output directory')

    args = parser.parse_args()

    generator = TerraformGenerator(args.output_dir)
    generator.generate_all_files()


if __name__ == "__main__":
    main()