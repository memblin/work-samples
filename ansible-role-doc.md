# Role Info: ha-haproxy

The `ha-haproxy` role should provide the configuration and resources for a Linux Server to run HAProxy and Keepalived in containers.

## Configurations

- Installs role supporting packages
- Sets net.ipv4.ip_nonlocal_bind in /etc/sysctl.d/local.conf
- Updates the sshd_config ListenAddress the host specific IP
- Restarts sshd if sshd_config is updated during the run
- Creates a `devops` Python3 virtual environment to use so we can avoid pip installing requirements as root
- Builds and installs the PyYAML module from source because PyYAML via is having build issues
  - Issues were preventing pip installation of `docker` and `docker-compose` required by `community.docker.docker_compose`.
- Completes pip installs for required Python modules into `devops` venv.
- Downloads SSL Certificate and Key from Hashicorp Vault
- Creates /opt/<project_root> directory
- Gets SSL, GitHub, and HAProxy secrets from Hashicorp Vault
- Gets GitHub ReadOnly token
- Clones the ha-haproxy repo into /opt/<project-root>/ha-haproxy
- Creates some config directories under the project directory
- Downloads Keepalived source tarball
- Renders HAProxy main configuration
- Renders HAProxy dataplaneapi configuration
  - Or removes it if dataplaneapi is disabled
- Deploys SSL Certificates and Private Keys
- Renders Keepalived configuration
- Creates containers and starts role services

## Useful Tags

- **render_configs**: Re-render all HAProxy and Keepalived configuration files
- **update_acls**: Copy static ACL files and re-render ACL templates
- **update_ssl**: Update SSL Certificate and Key and reload HAProxy
- **docker_compose**: Run only the docker_compose step
- **ha_haproxy**: Run only the tasks from the ha_haproxy role

## Handlers

- Load updated sysctl settings: `sysctl --system`
- Reload HAProxy: Saves server statuses to a file and HUPs haproxy (non-disruptive)
- Restart HAProxy: Saves server statuses to a file and restarts haproxy (disruptive)
- Restart keepalived: Restarts keepalived (potentially disruptive)

## Configuration Files

| Config File  | Purpose | Type |
| ------------ | --- | --- |
| haproxy.cfg | The HAProxy main config file. | Template |
| dataplaneapi.yml | The HAProxy dataplane API configuration | Template |
| keepalived.conf | The keepalivd configuration file | Template |

### Inventory Examples

These are examples of inventory objects used in the role. These variables are used to render the haproxy.cfg, dataplaneapi.yml, and keepalived.conf configuration files.

```yaml
# Inventory example sanitized for public consumption
```

## Supported OS

These are OS and Versions the role is known to work with.

- Ubuntu 22.04

