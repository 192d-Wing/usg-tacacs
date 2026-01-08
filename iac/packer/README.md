# TACACS+ Server Golden Image

Packer templates for building TACACS+ server golden images.

## Directory Structure

```
packer/
├── tacacs-server.pkr.hcl   # Main Packer template
├── scripts/
│   ├── base-setup.sh       # OS base configuration
│   ├── install-tacacs.sh   # TACACS+ binary installation
│   └── harden.sh           # Security hardening
├── files/
│   └── tacacs-server.service  # systemd unit template
└── README.md
```

## Features

The golden image includes:

- Pre-installed TACACS+ server binary
- systemd service unit with security hardening
- tacacs user/group created
- Required directories created with proper permissions
- Base firewall rules configured
- SSH hardening
- Kernel security parameters
- Audit logging configuration
- Login banners

## Building

### Prerequisites

1. Install Packer 1.9+
2. Install required plugins:
   ```bash
   packer init tacacs-server.pkr.hcl
   ```

### Building with QEMU (local testing)

```bash
packer build \
  -var "tacacs_binary_url=https://your-artifacts/tacacs-server-0.76.0-linux-amd64" \
  -var "tacacs_version=0.76.0" \
  tacacs-server.pkr.hcl
```

### Building with VMware vSphere

1. Uncomment the vsphere-iso source in `tacacs-server.pkr.hcl`
2. Create a variables file:
   ```hcl
   # vsphere.pkrvars.hcl
   vsphere_server     = "vcenter.example.com"
   vsphere_user       = "administrator@vsphere.local"
   vsphere_password   = "password"
   vsphere_datacenter = "DC1"
   vsphere_cluster    = "Cluster1"
   vsphere_datastore  = "datastore1"
   vsphere_network    = "VM Network"
   ```
3. Build:
   ```bash
   packer build \
     -var-file=vsphere.pkrvars.hcl \
     -var "tacacs_binary_url=..." \
     tacacs-server.pkr.hcl
   ```

### Building for AWS

1. Uncomment the amazon-ebs source
2. Configure AWS credentials
3. Build:
   ```bash
   packer build \
     -var "tacacs_binary_url=s3://your-bucket/tacacs-server" \
     tacacs-server.pkr.hcl
   ```

## Customization

### Adding Packages

Edit `scripts/base-setup.sh` to add additional packages.

### Custom Hardening

Edit `scripts/harden.sh` to adjust security settings.

### Different Base OS

Update the `iso_url` and `boot_command` in the source block.

## Output

After a successful build:
- `output/<image-name>/` - Built image files
- `output/manifest.json` - Build manifest with metadata

## Integration with Terraform

The output image can be used as the `template_name` variable in the Terraform `tacacs-vm` module.

## Security Considerations

The golden image is pre-hardened but requires:
- TLS certificates to be deployed by Ansible
- Shared secret to be configured (never in the image)
- LDAP credentials to be configured via Ansible Vault
- SSH keys to be injected at deploy time

## License

Apache-2.0
