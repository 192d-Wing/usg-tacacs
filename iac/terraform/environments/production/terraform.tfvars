# SPDX-License-Identifier: AGPL-3.0-only
# Production Environment - Variable Values
#
# Copy this file and customize for your environment

locations = {
  NYC01 = {
    vlan_id     = 100
    subnet_cidr = "10.1.1.0/24"
    gateway     = "10.1.1.1"
    vm_size     = "medium"
    vm_count    = 2
  }

  LAX01 = {
    vlan_id     = 200
    subnet_cidr = "10.2.1.0/24"
    gateway     = "10.2.1.1"
    vm_size     = "medium"
    vm_count    = 2
  }

  CHI01 = {
    vlan_id     = 300
    subnet_cidr = "10.3.1.0/24"
    gateway     = "10.3.1.1"
    vm_size     = "medium"
    vm_count    = 2
  }

  # Add more locations as needed...
}

global_tags = {
  environment = "production"
  application = "tacacs"
  team        = "network-ops"
  cost_center = "infrastructure"
}

management_cidrs = [
  "10.0.0.0/8"  # Internal management network
]

ssh_keys = [
  # Add SSH public keys here
  # "ssh-rsa AAAAB3... user@host"
]
