# SPDX-License-Identifier: AGPL-3.0-only
# Production Environment - TACACS+ Infrastructure

terraform {
  required_version = ">= 1.5.0"

  # Uncomment and configure your backend
  # backend "s3" {
  #   bucket         = "terraform-state"
  #   key            = "tacacs/production/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "terraform-locks"
  # }
}

# ============================================================================
# Provider Configuration (uncomment appropriate provider)
# ============================================================================

# provider "vsphere" {
#   vsphere_server       = var.vsphere_server
#   user                 = var.vsphere_user
#   password             = var.vsphere_password
#   allow_unverified_ssl = false
# }

# provider "aws" {
#   region = var.aws_region
# }

# ============================================================================
# Variables
# ============================================================================

variable "locations" {
  description = "Map of locations to deploy"
  type = map(object({
    vlan_id     = number
    subnet_cidr = string
    gateway     = string
    vm_size     = optional(string, "medium")
    vm_count    = optional(number, 2)
  }))
}

variable "global_tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    environment = "production"
    application = "tacacs"
    managed_by  = "terraform"
  }
}

variable "ssh_keys" {
  description = "SSH public keys for access"
  type        = list(string)
  default     = []
}

variable "management_cidrs" {
  description = "CIDRs for SSH management access"
  type        = list(string)
  default     = []
}

# ============================================================================
# Module Instantiation
# ============================================================================

module "tacacs_network" {
  source   = "../../modules/tacacs-network"
  for_each = var.locations

  location             = each.key
  vlan_id              = each.value.vlan_id
  subnet_cidr          = each.value.subnet_cidr
  gateway              = each.value.gateway
  management_cidrs     = var.management_cidrs
  tags                 = var.global_tags
}

module "tacacs_vm" {
  source   = "../../modules/tacacs-vm"
  for_each = var.locations

  location       = each.key
  instance_count = each.value.vm_count
  vm_size        = each.value.vm_size
  network_id     = tostring(each.value.vlan_id)
  subnet_cidr    = each.value.subnet_cidr
  gateway        = each.value.gateway
  ssh_keys       = var.ssh_keys
  tags           = var.global_tags

  depends_on = [module.tacacs_network]
}

module "tacacs_dns" {
  source   = "../../modules/tacacs-dns"
  for_each = var.locations

  location      = each.key
  instance_ips  = module.tacacs_vm[each.key].instance_ips
  vip_address   = module.tacacs_vm[each.key].vip_address

  depends_on = [module.tacacs_vm]
}

# ============================================================================
# Outputs
# ============================================================================

output "locations" {
  description = "Deployed locations"
  value       = keys(var.locations)
}

output "network_summary" {
  description = "Network configuration per location"
  value = {
    for loc, net in module.tacacs_network : loc => {
      subnet  = net.subnet_cidr
      vlan_id = net.vlan_id
    }
  }
}

output "vm_summary" {
  description = "VM configuration per location"
  value = {
    for loc, vm in module.tacacs_vm : loc => {
      instances = vm.instance_names
      ips       = vm.instance_ips
      vip       = vm.vip_address
    }
  }
}

output "dns_summary" {
  description = "DNS records per location"
  value = {
    for loc, dns in module.tacacs_dns : loc => dns.fqdns
  }
}

output "ansible_inventory" {
  description = "Generated Ansible inventory"
  value       = join("\n", [for loc, vm in module.tacacs_vm : vm.ansible_inventory_entry])
}
