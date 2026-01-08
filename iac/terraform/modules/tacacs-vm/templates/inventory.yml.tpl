# Auto-generated Ansible inventory for ${location}
${lower(location)}_ha:
  hosts:
%{ for idx, ip in instance_ips ~}
    ${vm_name_base}-${format("%02d", idx + 1)}:
      ansible_host: ${ip}
      tacacs_location: ${location}
      tacacs_ha_priority: ${idx == 0 ? 100 : 90}
%{ endfor ~}
  vars:
    tacacs_ha_vip: "${vip_address}"
