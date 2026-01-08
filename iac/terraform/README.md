# TACACS+ Terraform Infrastructure

Terraform modules for provisioning TACACS+ server infrastructure.

## Directory Structure

```
terraform/
├── modules/
│   ├── tacacs-vm/          # VM provisioning
│   ├── tacacs-network/     # Network/firewall configuration
│   └── tacacs-dns/         # DNS record management
├── environments/
│   ├── production/         # Production environment
│   │   ├── main.tf
│   │   ├── terraform.tfvars
│   │   └── locations/      # Per-location overrides
│   └── staging/            # Staging environment
└── README.md
```

## Modules

### tacacs-vm

Creates TACACS+ server VMs. Supports multiple providers (VMware vSphere, Proxmox, AWS).

**Key variables:**
- `location`: Location identifier (e.g., "NYC01")
- `instance_count`: Number of VMs (default: 2 for HA)
- `vm_size`: VM size (small/medium/large)
- `subnet_cidr`: Network CIDR for IP allocation

**Outputs:**
- `instance_ips`: List of VM IP addresses
- `vip_address`: Virtual IP for HA
- `ansible_inventory_entry`: Ready-to-use Ansible inventory

### tacacs-network

Configures network infrastructure including VLANs, subnets, and firewall rules.

**Key variables:**
- `vlan_id`: VLAN identifier
- `subnet_cidr`: Subnet CIDR
- `allowed_client_cidrs`: CIDRs allowed to access TACACS+

### tacacs-dns

Creates DNS records for TACACS+ servers and VIPs.

**Key variables:**
- `instance_ips`: IP addresses of instances
- `vip_address`: Virtual IP address
- `domain`: DNS domain (default: tacacs.internal)

## Quick Start

1. Configure your backend in `environments/production/main.tf`

2. Customize variables in `terraform.tfvars`:
   ```hcl
   locations = {
     NYC01 = {
       vlan_id     = 100
       subnet_cidr = "10.1.1.0/24"
       gateway     = "10.1.1.1"
     }
   }
   ```

3. Initialize and apply:
   ```bash
   cd environments/production
   terraform init
   terraform plan
   terraform apply
   ```

4. Generate Ansible inventory:
   ```bash
   terraform output -raw ansible_inventory > ../../ansible/inventory/production/hosts.yml
   ```

## Provider Configuration

The modules include commented examples for:
- VMware vSphere
- Proxmox VE
- AWS EC2

Uncomment the appropriate sections in each module and configure the provider in your environment.

## Adding New Locations

1. Add location to `terraform.tfvars`:
   ```hcl
   locations = {
     NYC01 = { ... }
     NEW_LOCATION = {
       vlan_id     = 400
       subnet_cidr = "10.4.1.0/24"
       gateway     = "10.4.1.1"
       vm_size     = "medium"
       vm_count    = 2
     }
   }
   ```

2. Apply changes:
   ```bash
   terraform apply
   ```

3. Update Ansible inventory with output.

## Integration with Ansible

The `tacacs-vm` module outputs an `ansible_inventory_entry` that can be used directly:

```bash
# Generate complete inventory
terraform output -json vm_summary | jq -r 'to_entries | .[] |
  "\(.key):\n  hosts:\n" +
  (.value.instances | to_entries | map("    \(.value):\n      ansible_host: \(.value.ips[.key])") | join("\n"))'
```

## License

Apache-2.0
