# SPDX-License-Identifier: AGPL-3.0-only
# TACACS+ Network Module
#
# Creates network infrastructure for TACACS+ servers including:
# - VLANs/Subnets
# - Firewall rules
# - Security groups

terraform {
  required_version = ">= 1.5.0"
}

variable "location" {
  description = "Location identifier"
  type        = string
}

variable "vlan_id" {
  description = "VLAN ID for TACACS+ network"
  type        = number
}

variable "subnet_cidr" {
  description = "Subnet CIDR"
  type        = string
}

variable "gateway" {
  description = "Default gateway"
  type        = string
}

variable "allowed_client_cidrs" {
  description = "CIDRs allowed to access TACACS+"
  type        = list(string)
  default     = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
}

variable "management_cidrs" {
  description = "CIDRs allowed for SSH management"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags to apply"
  type        = map(string)
  default     = {}
}

locals {
  common_tags = merge(var.tags, {
    service  = "tacacs"
    location = var.location
    managed  = "terraform"
  })
}

# ============================================================================
# Firewall Rules (platform-agnostic representation)
# ============================================================================

locals {
  firewall_rules = {
    # TACACS+ legacy port
    tacacs_legacy = {
      name        = "allow-tacacs-legacy"
      direction   = "ingress"
      protocol    = "tcp"
      port        = 49
      source      = var.allowed_client_cidrs
      description = "Allow TACACS+ legacy port from network devices"
    }

    # TACACS+ TLS port
    tacacs_tls = {
      name        = "allow-tacacs-tls"
      direction   = "ingress"
      protocol    = "tcp"
      port        = 300
      source      = var.allowed_client_cidrs
      description = "Allow TACACS+ TLS port from network devices"
    }

    # Health check / metrics port (internal only)
    health = {
      name        = "allow-health-internal"
      direction   = "ingress"
      protocol    = "tcp"
      port        = 8080
      source      = [var.subnet_cidr]
      description = "Allow health checks from within TACACS+ subnet"
    }

    # SSH management
    ssh = {
      name        = "allow-ssh-mgmt"
      direction   = "ingress"
      protocol    = "tcp"
      port        = 22
      source      = var.management_cidrs
      description = "Allow SSH from management networks"
    }

    # VRRP for keepalived (between HA pairs)
    vrrp = {
      name        = "allow-vrrp"
      direction   = "ingress"
      protocol    = "vrrp"
      port        = 0
      source      = [var.subnet_cidr]
      description = "Allow VRRP between HA pairs"
    }
  }
}

# ============================================================================
# AWS Security Group Example (uncomment to use)
# ============================================================================

# resource "aws_security_group" "tacacs" {
#   name        = "tacacs-${lower(var.location)}"
#   description = "Security group for TACACS+ servers"
#   vpc_id      = var.vpc_id
#
#   tags = local.common_tags
# }
#
# resource "aws_security_group_rule" "tacacs_legacy" {
#   security_group_id = aws_security_group.tacacs.id
#   type              = "ingress"
#   from_port         = 49
#   to_port           = 49
#   protocol          = "tcp"
#   cidr_blocks       = var.allowed_client_cidrs
#   description       = "TACACS+ legacy port"
# }
#
# resource "aws_security_group_rule" "tacacs_tls" {
#   security_group_id = aws_security_group.tacacs.id
#   type              = "ingress"
#   from_port         = 300
#   to_port           = 300
#   protocol          = "tcp"
#   cidr_blocks       = var.allowed_client_cidrs
#   description       = "TACACS+ TLS port"
# }

# ============================================================================
# Outputs
# ============================================================================

output "location" {
  value = var.location
}

output "subnet_cidr" {
  value = var.subnet_cidr
}

output "vlan_id" {
  value = var.vlan_id
}

output "firewall_rules" {
  description = "Firewall rules to be implemented"
  value       = local.firewall_rules
}
