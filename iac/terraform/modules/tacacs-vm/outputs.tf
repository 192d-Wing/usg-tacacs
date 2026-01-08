# SPDX-License-Identifier: AGPL-3.0-only
# TACACS+ VM Module - Outputs

output "location" {
  description = "Location identifier"
  value       = var.location
}

output "vm_size" {
  description = "VM size used"
  value       = var.vm_size
}

output "vm_specs" {
  description = "VM specifications"
  value       = local.specs
}

output "vm_count" {
  description = "Number of VMs created"
  value       = var.instance_count
}

output "network_config" {
  description = "Network configuration summary"
  value = {
    subnet     = var.subnet_cidr
    gateway    = var.gateway
    vip        = local.vip_address
    instances  = local.instance_ips
    dns        = var.dns_servers
  }
}

output "ansible_inventory_entry" {
  description = "Ansible inventory entry for this location"
  value = templatefile("${path.module}/templates/inventory.yml.tpl", {
    location      = var.location
    instance_ips  = local.instance_ips
    vip_address   = local.vip_address
    vm_name_base  = local.vm_name_base
  })
}
