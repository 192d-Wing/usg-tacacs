# SPDX-License-Identifier: AGPL-3.0-only
# TACACS+ VM Module - Main
#
# This module creates TACACS+ server VMs. It's designed to be provider-agnostic
# with examples for common platforms. Uncomment the appropriate resource blocks
# for your infrastructure.

terraform {
  required_version = ">= 1.5.0"
}

locals {
  vm_name_base = "${var.vm_name_prefix}-${lower(var.location)}"
  specs        = var.vm_specs[var.vm_size]
  subnet_base  = cidrhost(var.subnet_cidr, 0)

  # Generate IP addresses for each instance
  instance_ips = [
    for i in range(var.instance_count) : cidrhost(var.subnet_cidr, var.ip_offset + i)
  ]

  vip_address = cidrhost(var.subnet_cidr, var.vip_offset)

  common_tags = merge(var.tags, {
    service  = "tacacs"
    location = var.location
    managed  = "terraform"
  })
}

# ============================================================================
# VMware vSphere Example (uncomment to use)
# ============================================================================

# data "vsphere_datacenter" "dc" {
#   name = var.datacenter
# }
#
# data "vsphere_compute_cluster" "cluster" {
#   name          = var.cluster
#   datacenter_id = data.vsphere_datacenter.dc.id
# }
#
# data "vsphere_datastore" "datastore" {
#   name          = var.datastore
#   datacenter_id = data.vsphere_datacenter.dc.id
# }
#
# data "vsphere_network" "network" {
#   name          = var.network_id
#   datacenter_id = data.vsphere_datacenter.dc.id
# }
#
# data "vsphere_virtual_machine" "template" {
#   name          = var.template_name
#   datacenter_id = data.vsphere_datacenter.dc.id
# }
#
# resource "vsphere_virtual_machine" "tacacs" {
#   count = var.instance_count
#
#   name             = "${local.vm_name_base}-${format("%02d", count.index + 1)}"
#   resource_pool_id = data.vsphere_compute_cluster.cluster.resource_pool_id
#   datastore_id     = data.vsphere_datastore.datastore.id
#
#   num_cpus = local.specs.cpus
#   memory   = local.specs.memory
#
#   guest_id  = data.vsphere_virtual_machine.template.guest_id
#   scsi_type = data.vsphere_virtual_machine.template.scsi_type
#
#   network_interface {
#     network_id   = data.vsphere_network.network.id
#     adapter_type = data.vsphere_virtual_machine.template.network_interface_types[0]
#   }
#
#   disk {
#     label            = "disk0"
#     size             = local.specs.disk
#     thin_provisioned = true
#   }
#
#   clone {
#     template_uuid = data.vsphere_virtual_machine.template.id
#
#     customize {
#       linux_options {
#         host_name = "${local.vm_name_base}-${format("%02d", count.index + 1)}"
#         domain    = "tacacs.local"
#       }
#
#       network_interface {
#         ipv4_address = local.instance_ips[count.index]
#         ipv4_netmask = split("/", var.subnet_cidr)[1]
#       }
#
#       ipv4_gateway    = var.gateway
#       dns_server_list = var.dns_servers
#     }
#   }
#
#   tags = [for k, v in local.common_tags : "${k}:${v}"]
# }

# ============================================================================
# Proxmox VE Example (uncomment to use)
# ============================================================================

# resource "proxmox_vm_qemu" "tacacs" {
#   count = var.instance_count
#
#   name        = "${local.vm_name_base}-${format("%02d", count.index + 1)}"
#   target_node = var.proxmox_node
#   clone       = var.template_name
#
#   cores  = local.specs.cpus
#   memory = local.specs.memory
#
#   disk {
#     storage = var.datastore
#     size    = "${local.specs.disk}G"
#     type    = "scsi"
#   }
#
#   network {
#     model  = "virtio"
#     bridge = var.network_id
#   }
#
#   ipconfig0 = "ip=${local.instance_ips[count.index]}/${split("/", var.subnet_cidr)[1]},gw=${var.gateway}"
#
#   sshkeys = join("\n", var.ssh_keys)
#
#   tags = join(",", [for k, v in local.common_tags : "${k}=${v}"])
# }

# ============================================================================
# AWS EC2 Example (uncomment to use)
# ============================================================================

# data "aws_ami" "tacacs" {
#   most_recent = true
#   owners      = ["self"]
#
#   filter {
#     name   = "name"
#     values = [var.template_name]
#   }
# }
#
# resource "aws_instance" "tacacs" {
#   count = var.instance_count
#
#   ami           = data.aws_ami.tacacs.id
#   instance_type = var.vm_size == "small" ? "t3.small" : var.vm_size == "medium" ? "t3.medium" : "t3.large"
#   subnet_id     = var.network_id
#   private_ip    = local.instance_ips[count.index]
#
#   key_name = var.ssh_key_name
#
#   root_block_device {
#     volume_size = local.specs.disk
#     volume_type = "gp3"
#   }
#
#   tags = merge(local.common_tags, {
#     Name = "${local.vm_name_base}-${format("%02d", count.index + 1)}"
#   })
# }

# ============================================================================
# Placeholder output for documentation
# ============================================================================

output "instance_ips" {
  description = "IP addresses of TACACS+ instances"
  value       = local.instance_ips
}

output "vip_address" {
  description = "Virtual IP address for HA"
  value       = local.vip_address
}

output "instance_names" {
  description = "Names of TACACS+ instances"
  value       = [for i in range(var.instance_count) : "${local.vm_name_base}-${format("%02d", i + 1)}"]
}
