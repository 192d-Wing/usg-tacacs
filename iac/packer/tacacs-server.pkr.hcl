# SPDX-License-Identifier: AGPL-3.0-only
# Packer template for TACACS+ server golden image

packer {
  required_version = ">= 1.9.0"

  required_plugins {
    # Uncomment the plugin for your platform
    # vsphere = {
    #   version = ">= 1.2.0"
    #   source  = "github.com/hashicorp/vsphere"
    # }
    # proxmox = {
    #   version = ">= 1.1.0"
    #   source  = "github.com/hashicorp/proxmox"
    # }
    # amazon = {
    #   version = ">= 1.2.0"
    #   source  = "github.com/hashicorp/amazon"
    # }
    qemu = {
      version = ">= 1.0.0"
      source  = "github.com/hashicorp/qemu"
    }
  }
}

# ============================================================================
# Variables
# ============================================================================

variable "base_image" {
  type        = string
  description = "Base OS image (e.g., Rocky Linux 9, Ubuntu 22.04)"
  default     = "rocky-9"
}

variable "tacacs_version" {
  type        = string
  description = "TACACS+ server version"
  default     = "0.76.0"
}

variable "tacacs_binary_url" {
  type        = string
  description = "URL to download TACACS+ binary"
  default     = ""
}

variable "output_directory" {
  type        = string
  description = "Directory for output artifacts"
  default     = "output"
}

variable "ssh_username" {
  type        = string
  description = "SSH username for provisioning"
  default     = "packer"
}

variable "ssh_password" {
  type        = string
  description = "SSH password for provisioning"
  default     = "packer"
  sensitive   = true
}

# ============================================================================
# Local Variables
# ============================================================================

locals {
  timestamp   = formatdate("YYYYMMDD-hhmm", timestamp())
  image_name  = "tacacs-server-${var.tacacs_version}-${local.timestamp}"
  build_label = "tacacs-server-${var.tacacs_version}"
}

# ============================================================================
# QEMU Builder (for local testing)
# ============================================================================

source "qemu" "tacacs" {
  iso_url          = "https://download.rockylinux.org/pub/rocky/9/isos/x86_64/Rocky-9-latest-x86_64-minimal.iso"
  iso_checksum     = "file:https://download.rockylinux.org/pub/rocky/9/isos/x86_64/Rocky-9-latest-x86_64-minimal.iso.CHECKSUM"
  output_directory = "${var.output_directory}/${local.image_name}"
  vm_name          = local.image_name

  cpus             = 2
  memory           = 2048
  disk_size        = "20G"

  headless         = true
  accelerator      = "kvm"

  ssh_username     = var.ssh_username
  ssh_password     = var.ssh_password
  ssh_timeout      = "30m"

  shutdown_command = "sudo shutdown -h now"

  boot_wait        = "10s"
  boot_command     = [
    "<tab> inst.text inst.ks=http://{{ .HTTPIP }}:{{ .HTTPPort }}/ks.cfg<enter><wait>"
  ]

  http_directory   = "http"
}

# ============================================================================
# VMware vSphere Builder (uncomment to use)
# ============================================================================

# source "vsphere-iso" "tacacs" {
#   vcenter_server      = var.vsphere_server
#   username            = var.vsphere_user
#   password            = var.vsphere_password
#   insecure_connection = false
#
#   datacenter          = var.vsphere_datacenter
#   cluster             = var.vsphere_cluster
#   datastore           = var.vsphere_datastore
#   folder              = var.vsphere_folder
#
#   vm_name             = local.image_name
#   guest_os_type       = "rhel9_64Guest"
#
#   CPUs                = 2
#   RAM                 = 2048
#   RAM_reserve_all     = false
#
#   disk_controller_type = ["pvscsi"]
#   storage {
#     disk_size             = 20480
#     disk_thin_provisioned = true
#   }
#
#   network_adapters {
#     network      = var.vsphere_network
#     network_card = "vmxnet3"
#   }
#
#   iso_paths = [var.iso_path]
#
#   ssh_username = var.ssh_username
#   ssh_password = var.ssh_password
#   ssh_timeout  = "30m"
#
#   shutdown_command = "sudo shutdown -h now"
#
#   convert_to_template = true
# }

# ============================================================================
# Build Definition
# ============================================================================

build {
  name    = "tacacs-golden-image"
  sources = ["source.qemu.tacacs"]

  # Base system setup
  provisioner "shell" {
    script = "scripts/base-setup.sh"
    environment_vars = [
      "TACACS_VERSION=${var.tacacs_version}"
    ]
  }

  # Install TACACS+ server
  provisioner "shell" {
    script = "scripts/install-tacacs.sh"
    environment_vars = [
      "TACACS_VERSION=${var.tacacs_version}",
      "TACACS_BINARY_URL=${var.tacacs_binary_url}"
    ]
  }

  # Deploy systemd service file
  provisioner "file" {
    source      = "files/tacacs-server.service"
    destination = "/tmp/tacacs-server.service"
  }

  provisioner "shell" {
    inline = [
      "sudo mv /tmp/tacacs-server.service /etc/systemd/system/tacacs-server.service",
      "sudo systemctl daemon-reload",
      "sudo systemctl enable tacacs-server"
    ]
  }

  # Security hardening
  provisioner "shell" {
    script = "scripts/harden.sh"
  }

  # Cleanup
  provisioner "shell" {
    inline = [
      "sudo yum clean all || sudo apt-get clean",
      "sudo rm -rf /var/cache/* /tmp/* /var/tmp/*",
      "sudo truncate -s 0 /etc/machine-id",
      "sudo rm -f /etc/ssh/ssh_host_*",
      "sudo rm -f /root/.bash_history",
      "sudo rm -rf /home/*/.bash_history",
      "sudo sync"
    ]
  }

  post-processor "manifest" {
    output     = "${var.output_directory}/manifest.json"
    strip_path = true
    custom_data = {
      tacacs_version = var.tacacs_version
      build_time     = local.timestamp
    }
  }
}
