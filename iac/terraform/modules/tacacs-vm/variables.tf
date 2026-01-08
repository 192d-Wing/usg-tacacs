# SPDX-License-Identifier: AGPL-3.0-only
# TACACS+ VM Module - Variables

variable "location" {
  description = "Location identifier (e.g., NYC01)"
  type        = string
}

variable "instance_count" {
  description = "Number of TACACS+ instances to create (typically 2 for HA)"
  type        = number
  default     = 2
}

variable "vm_name_prefix" {
  description = "Prefix for VM names"
  type        = string
  default     = "tacacs"
}

variable "vm_size" {
  description = "VM size/flavor"
  type        = string
  default     = "medium"

  validation {
    condition     = contains(["small", "medium", "large"], var.vm_size)
    error_message = "vm_size must be one of: small, medium, large"
  }
}

variable "vm_specs" {
  description = "VM specifications per size"
  type = map(object({
    cpus   = number
    memory = number
    disk   = number
  }))
  default = {
    small = {
      cpus   = 2
      memory = 2048
      disk   = 20
    }
    medium = {
      cpus   = 4
      memory = 4096
      disk   = 50
    }
    large = {
      cpus   = 8
      memory = 8192
      disk   = 100
    }
  }
}

variable "network_id" {
  description = "Network/VLAN ID for TACACS+ servers"
  type        = string
}

variable "subnet_cidr" {
  description = "Subnet CIDR for IP allocation"
  type        = string
}

variable "ip_offset" {
  description = "Starting IP offset within subnet (e.g., 11 for .11)"
  type        = number
  default     = 11
}

variable "vip_offset" {
  description = "VIP IP offset within subnet (e.g., 100 for .100)"
  type        = number
  default     = 100
}

variable "gateway" {
  description = "Default gateway IP"
  type        = string
}

variable "dns_servers" {
  description = "DNS server IPs"
  type        = list(string)
  default     = ["8.8.8.8", "8.8.4.4"]
}

variable "ssh_keys" {
  description = "SSH public keys for access"
  type        = list(string)
  default     = []
}

variable "template_name" {
  description = "VM template/image name"
  type        = string
  default     = "tacacs-golden-image"
}

variable "datastore" {
  description = "Datastore for VM disks"
  type        = string
  default     = "datastore1"
}

variable "cluster" {
  description = "Compute cluster name"
  type        = string
  default     = "cluster1"
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}
