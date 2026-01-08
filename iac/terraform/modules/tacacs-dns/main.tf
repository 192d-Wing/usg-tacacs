# SPDX-License-Identifier: AGPL-3.0-only
# TACACS+ DNS Module
#
# Creates DNS records for TACACS+ servers and VIPs

terraform {
  required_version = ">= 1.5.0"
}

variable "location" {
  description = "Location identifier"
  type        = string
}

variable "domain" {
  description = "DNS domain"
  type        = string
  default     = "tacacs.internal"
}

variable "instance_ips" {
  description = "IP addresses of TACACS+ instances"
  type        = list(string)
}

variable "vip_address" {
  description = "Virtual IP address"
  type        = string
}

variable "vm_name_prefix" {
  description = "Prefix for VM names"
  type        = string
  default     = "tacacs"
}

variable "ttl" {
  description = "DNS record TTL"
  type        = number
  default     = 300
}

variable "zone_id" {
  description = "DNS zone ID (provider-specific)"
  type        = string
  default     = ""
}

locals {
  location_lower = lower(var.location)
  base_name      = "${var.vm_name_prefix}-${local.location_lower}"

  # Individual server records
  a_records = {
    for idx, ip in var.instance_ips :
    "${local.base_name}-${format("%02d", idx + 1)}" => ip
  }

  # VIP record for the location
  vip_record = {
    "${local.base_name}" = var.vip_address
  }
}

# ============================================================================
# AWS Route53 Example (uncomment to use)
# ============================================================================

# resource "aws_route53_record" "tacacs_instances" {
#   for_each = local.a_records
#
#   zone_id = var.zone_id
#   name    = "${each.key}.${var.domain}"
#   type    = "A"
#   ttl     = var.ttl
#   records = [each.value]
# }
#
# resource "aws_route53_record" "tacacs_vip" {
#   for_each = local.vip_record
#
#   zone_id = var.zone_id
#   name    = "${each.key}.${var.domain}"
#   type    = "A"
#   ttl     = var.ttl
#   records = [each.value]
# }

# ============================================================================
# Outputs
# ============================================================================

output "dns_records" {
  description = "DNS records to be created"
  value = {
    instances = local.a_records
    vip       = local.vip_record
    domain    = var.domain
    ttl       = var.ttl
  }
}

output "fqdns" {
  description = "Fully qualified domain names"
  value = {
    instances = [for name, _ in local.a_records : "${name}.${var.domain}"]
    vip       = [for name, _ in local.vip_record : "${name}.${var.domain}"]
  }
}
