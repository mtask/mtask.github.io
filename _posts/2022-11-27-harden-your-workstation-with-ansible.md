---
title: 'Hardening Linux workstation with Ansible'
layout: 'post'
tags: ["Security", "Ansible"]
---

{:toc}

While Ansible's most common use-case is to provision multiple hosts over SSH it can be used very nicely to provision local systems as well.

I usually use Ansible to configure and harden some basic things with my workstations and have different playbook setups for different things.
I recently published one hardening tooling setup to Github.

This post covers how that project can be used to harden workstations. 
You can find the published project [here](https://github.com/mtask/ansible-secure-workstation) and its main documentation will be this post.

Check [Ansible Collection - devsec.hardening](https://github.com/dev-sec/ansible-collection-hardening) for more full-blown hardening role for Ansible.
My project does not try to do the exactly same or at least not to same extent. My main focus is to setup basic hardening for a local workstation installation.


## Introduction and project's structure

The project contains one main provisioning playbook, some helper playbooks, and helper scripts. The project structure looks like this at the moment:

```
.
├── common
│   ├── files
│   │   └── backup.sh
│   ├── tasks
│   │   ├── backups.yml
│   │   └── common.yml
│   └── templates
│       └── rsnapshot.conf.j2
├── helper-scripts
│   ├── aide-check.sh
│   └── audit-today.sh
├── inventory
│   ├── hosts
│   └── host_vars
│       └── local.yml
├── README.md
├── roles
│   ├── install-lynis
│   │   └── tasks
│   │       └── main.yml
│   ├── install-veracrypt
│   │   └── tasks
│   │       └── main.yml
│   └── workstation-hardening
│       ├── defaults
│       │   └── main.yml
│       ├── files
│       ├── README.md
│       ├── tasks
│       │   ├── aide.yml
│       │   ├── apparmor.yml
│       │   ├── auditd.yml
│       │   ├── clamav.yml
│       │   ├── grub_cmd_ipv6_apparmor.yml
│       │   ├── kernel.yml
│       │   ├── main.yml
│       │   ├── misc.yml
│       │   ├── service_file_hardening.yml
│       │   ├── systemd.yml
│       │   ├── ufw.yml
│       │   └── usbguard.yml
│       ├── templates
│       │   ├── aide.conf
│       │   ├── apparmor
│       │   │   └── usr.sbin.wpa_supplicant.j2
│       │   ├── auditd
│       │   │   ├── 10-base-config.rules
│       │   │   ├── 30-stig.rules
│       │   │   ├── 40-custom.rules
│       │   │   └── 99-finalize.rules
│       │   ├── clamd.conf.j2
│       │   ├── clamonacc.service.j2
│       │   └── tmp.mount.j2
│       └── vars
│           └── main.yml
├── update-aide.yml
├── update-system.yml
└── workstsation.yml
```

The `workstsation.yml` is the main provisioning script and does the following:

* Install packages defined in `common_packages`. These are not dependencies and can be modified based on what is needed on the target machine.
* Provision `rsnapshot` for taking incremental backups.
* Install Veracrypt for encryption needs.
* Install Lynis for auditing security configuration.
* Run hardening tasks defined in `workstation-hardening` role.

The `workstation-hardening` role contains main hardening tasks. The role is categorized to somewhat logical sub sections (e.g. `systemd`, `kernel`, `auditd`, etc).
Each sub section **should** more or less be self contained and those can be executed using `--tags <section tag>`.

The basic ideology is to use common de-facto Linux tooling which are usually recommended by many hardening guides (e.g. CIS and STIG). 
Many of those solutions could be replaced with third-party tools which can have all sort of bells and whistles, but I purposely tried to avoid going that route.
Fancy solutions quickly means some full-blown ecosystem, which means agents and servers, and I want this setup to be usable without that sort of external dependencies.

Summary of `workstation-hardening` role's actions:

*  Configure UFW firewall (ufw.yml)
*  Misc hardening actions (misc.yml)
    * Set `/etc/issue` and `/etc/issue.net`
    * Disable core dumps
    * Allow root only to use crontab
    * Configure login.defs
    * Set home directory permissions to 750
    * Harden `/tmp` and `/dev/shm`
    * Harden different file permissions (list in variable)
    * Install and configure system accounting (acct) and statistics (sysstat)
    * Configure access.conf
      * Allow local login for root and current user by default.
*  Configure ClamAV virus scanner (clamav.yml)
    * On-Access scan enabled in `~/Downloads` by default.
*  Configure Auditd (auditd.yml)
*  Systemd unit file hardening and disable some services with high attack surface (systemd.yml)
*  Configure USBGuard (usbguard.yml)
    * By default allows devices that are inserted during the provisioning.
*  Configure Apparmor (apparmor.yml)
    * Enforces existing profiles under `/etc/apparmor.d`
      * Takes also a list of profiles that should not be enforces (empty by default).
    * Enforces selected profiles from `apparmor-extra-profiles`.
    * Allows importing own custom profiles.
*  Ensure that Apparmor is enabled early in boot and IPv6 is disabled (grub_cmd_ipv6_apparmor.yml)
*  Harden some kernel configuration (kernel.yml)
    * Disable (usually) some unnecessary kernel module.
    * Configure sysctl parameters.
*  Configure Advanced Intrusion Detection Environment - AIDE (aide.yml)

### Project's Ansible variables

#### `workstation-hardening` role's variables:

* `hardened_kernel_params` -\> Dict of sysctl parameters to set. For example:

```yaml
hardened_kernel_params:
  fs.suid_dumpable: "0"
  fs.protected_fifos: "2"
  fs.protected_hardlinks: "1"
```

* `etc_issue_and_issue_net_content` -\> Content of `/etc/issue` and `/etc/issue.net` (string).
* `systemd_services_to_stop_and_disable` -\> List of service names that should be stopped and disabled.
* `ufw` -\> UFW firewall settings. For example:

```yaml
ufw:
  # Input policy is always deny
  policy_out: allow
  tcp_allow_out:
  - '80'
  - '443'
  - '53'
  - '22'
  udp_allow_out:
  - '123'
  - '53'
  - '67'
  - '68'
```

* `systemd_unit_files_to_harden` -\> Hardening parameters for systemd services' unit files. For example:

```yaml
systemd_unit_files_to_harden:
  - path: /lib/systemd/system/unattended-upgrades.service
    lines:
      - 'PrivateDevices=yes'
      - 'ProtectControlGroups=yes'
  - path: /lib/systemd/system/clamav-freshclam.service
    lines:
      - 'PrivateDevices=yes'
      - 'ProtectControlGroups=yes'
      - 'ProtectHome=yes'
```

* `file_permissions` -\> List of file paths and wanter file permissions. For example:

```
file_permissions:
   - path: /etc/cron.daily
     mode: '700'
     state: directory
   - path: /boot/grub/grub.cfg
     mode: '600'
     state: file
```

* `access_conf_content` -\> Content for `/etc/security/access.conf`. For example:

```yaml
access_conf_content: |
  +:root:LOCAL
  +:{% raw %}{{ lookup('env', 'USER') }}:{% endraw %}LOCAL
  -:ALL:ALL
```

* `apparmor` -\> Apparmor configuration. For example:

```yaml
apparmor:
  # Apparmor related packages to be installed
  packages:
    - apparmor
    - apparmor-utils
    - apparmor-profiles
    - apparmor-profiles-extra
  # Path where extra profiles from apparmor-profiles-extra are found
  # (This varies a bit between distributions)
  extra_profiles_path: '/usr/share/apparmor/extra-profiles/'
  # List of extra profiles to enforce
  extra_profiles_enforce:
    - bin.netstat
    - sbin.dhclient
    - sbin.dhclient-script
    - usr.bin.apropos
    - usr.bin.man
    - usr.bin.passwd
    - usr.lib.man-db.man
    - usr.sbin.postalias
    - usr.sbin.postdrop
    - usr.sbin.postmap
    - usr.sbin.postqueue
    - usr.sbin.sendmail
    - usr.sbin.useradd
    - usr.sbin.userdel
  # Keep these profiles in complain mode
  # e.g. ["usr.sbin.userdel"]
  complain_profiles: []
  # Custom profiles to copy from a template and enforce
  custom_profile_templates:
    - 'apparmor/usr.sbin.wpa_supplicant.j2'

```

* `login_defs_setting_lines` -\> `/etc/login.defs` lines. For example:

```yaml
login_defs_setting_lines:
  - ['^PASS_MAX_DAYS.*', 'PASS_MAX_DAYS   365']
  - ['^UMASK.*', 'UMASK           027']
  - ['^PASS_MIN_DAYS.*', 'PASS_MIN_DAYS   1']
```

* `modpobe_disable` -\> Kernel modules to disable. For example:

```yaml
modpobe_disable:
  - path: /etc/modprobe.d/cramfs.conf
    line: 'install cramfs /bin/true'
  - path: /etc/modprobe.d/freevxfs.conf
    line: 'install freevxfs /bin/true'
  - path: /etc/modprobe.d/jffs2.conf
    line: 'install jffs2 /bin/true'
  - path: /etc/modprobe.d/hfs.conf
    line: 'install /bin/true'
  - path: /etc/modprobe.d/hfsplus.conf
    line: 'install hfsplus /bin/true'
  - path: /etc/modprobe.d/udf.conf
    line: 'install udf /bin/true'
  - path: /etc/modprobe.d/dccp.conf
    line: 'install dccp /bin/true'
  - path: /etc/modprobe.d/sctp.conf
    line: 'install sctp /bin/true'
  - path: /etc/modprobe.d/rds.conf
    line: 'install rds /bin/true'
  - path: /etc/modprobe.d/tipc.conf
    line: 'install tipc /bin/true'
```

* `aide_monitor_paths` -\> Paths to monitor with AIDE. For example:

```yaml
aide_monitor_paths:
  - '/etc Full'
  - '/usr/local/sbin Full'
  - '/usr/local/bin Full'
  - '/usr/sbin Full'
  - '/usr/bin/sbin Full'
  - '/bin Full'
  - '/lib Full'
  - '/opt Full'
  - '/snap/bin Full'
  - "{% raw %}{{ lookup('env', 'HOME') }}/.bashrc Full"{% endraw %}
  - "{% raw %}{{ lookup('env', 'HOME') }}/.ssh Full{% endraw %}"
  - "{% raw %}{{ lookup('env', 'HOME') }}/.config/autostart Full{% endraw %}"
```

#### Other variables

* `common_packages` -\> Arbitrary list of packages you want to install.
* `rsnapshot_backups` -\> Configuration for rsnapshot backups. For example:

```yaml
rsnapshot_backups:
  # What to backup
  src_paths:
    - "/home/"
    - '/etc/'
    - '/var/log/audit/'
    - '/var/lib/aide/aide.db'
  # Where to backup
  snapshot_root: "/media/ext-hdd/backups-2022/hostX"

```

## Preparations

### Dependencies:

* Ubuntu or Debian installation 
* Ansible (tested with ansible-core version 2.13.6) locally installed on the target machine as the project uses local connection.

### Configure variables

Go through `roles/workstation-hardening/defaults/main.yml` and `inventory/host_vars/local.yml` and set suitable values for you. 
Common practice is to keep role's variables as is and override those in your inventory.


### Configure auditd rules

Auditd rules are defined as Jinja2 templates and can be found in `roles/workstation-hardening/templates/auditd/`. 
All files in that directory are copied to auditd rules.

### Adding your own Apparmor profiles

Give paths to your profile files in variable `apparmor.custom_profile_templates`. 
These are treated as Jinja2 templates, so you can use Jinj2 syntax inside profiles.

### Configure AIDE

AIDE configuration is Jinj2 template found in path `roles/workstation-hardening/templates/aide.conf`.
In variable `aide_monitor_paths` you can list paths to monitor with AIDE. 
For other configuration changes you need to modify the template.

## Usage

Initial provisioning is very simple and it only requires running one playbook.

* Run `ansible-playbook -i inventory/hosts workstsation.yml` to provision everything.
* Use tags to run or skip specifc task(s). Use `ansible-playbook -i inventory/hosts workstsation.yml --list-tags` to list available tags.
  * For example, run only apparmor: `--tags apparmor`
  * For example, skip apparmor: `--skip-tags apparmor`


### Helper scripts and playbooks

The project contains some helper scripts and playbooks that can be used after initial provisioning.

#### helper-scripts/aide-check.sh

Check system changes against AIDE database: `sudo ./helper-scripts/aide-check.sh` 

#### update-aide.yml

Update aide database: `ansible-playbook -i inventory/hosts update-aide.yml` -\> Update AIDE database.

#### helper-scripts/audit-today.sh

Get audit report for "todays" events: `sudo ./helper-scripts/audit-today.sh`

Example report:

```md
Summary Report
======================
Range of time in logs: 01.01.1970 02:00:00.000 - 23.11.2022 17:06:51.467
Selected time for report: 23.11.2022 00:00:00 - 23.11.2022 17:06:51.467
Number of changes in configuration: 0
Number of changes to accounts, groups, or roles: 0
Number of logins: 0
Number of failed logins: 0
Number of authentications: 1
Number of failed authentications: 1
Number of users: 3
Number of terminals: 13
Number of host names: 2
Number of executables: 30
Number of commands: 104
Number of files: 14088
Number of AVC's: 0
Number of MAC events: 0
Number of failed syscalls: 161
Number of anomaly events: 2
Number of responses to anomaly events: 0
Number of crypto events: 0
Number of integrity events: 0
Number of virt events: 0
Number of keys: 3
Number of process IDs: 368
Number of events: 30608


Account Modifications Report
=================================================
# date time auid addr term exe acct success event
=================================================
<no events of interest were found>


Anomaly Report
=========================================
# date time type exe term host auid event
=========================================
1. 23.11.2022 10:57:15 ANOM_RBAC_INTEGRITY_FAIL /usr/bin/aide ? ? -1 15181
2. 23.11.2022 12:05:03 ANOM_RBAC_INTEGRITY_FAIL /usr/bin/aide pts/4 e15 1000 33891

ClamAV quarantine
=================

<no matches>
```
  
* `update-system.yml` -\> Upgrade system and update AIDE database after upgrade.

### Backups 

The `workstsation.yml` playbook provisions the following Rsnapshot installation:

```
/opt/rsnapshot/
├── backup.sh
└── rsnapshot.conf
```

The `backup.sh` is just a wrapper for the `rsnapshot` command that uses `/opt/rsnapshot/rsnapshot.conf` as its configuration.
The configuration is populated based on `rsnapshot_backups` variable.
Run using `sudo ./backup.sh`.

## Other hardening sources

* My other blog post about [Securing Linux workstation](/2021/11/16/securing-linux-workstations.html).
    * Contains some hardening tips that is not yet implemented in this project. 
* [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
* [STIG](https://www.stigviewer.com/stigs)
* [https://madaidans-insecurities.github.io/guides/linux-hardening.html](https://madaidans-insecurities.github.io/guides/linux-hardening.html) 
