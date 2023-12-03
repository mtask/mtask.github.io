---
title: 'Securing Linux workstations'
layout: 'post'
tags: ["Security"]

---

{:toc}

In this post, I list some tips and tricks for securing Linux workstations. I have used Ubuntu 20.04 LTS as a reference for testing these things, but most of the examples listed in this post, are valid at least for other Debian-based distributions. 

This is not a step-by-step guide but contains some information to get one started with Linux workstation security.

## Operating system hardening

### Automated security updates (unattended-upgrades)

* Install unattended-upgrades: `sudo apt install unattended-upgrades`
* Ensure that the service is enabled and started: `systemctl status unattended-upgrades`
* Run `sudo dpkg-reconfigure --priority=low unattended-upgrades` and answer "yes" to enable automated upgrades
* Edit `etc/apt/apt.conf.d/50unattended-upgrades` and ensure that `"${distro_id}:${distro_codename}-security";` is not commented out (there's no `//` in the beginning of the line)
* Ensure that `/etc/apt/apt.conf.d/20auto-upgrades` has (at least) the following lines:

```
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
```

* Test with command `sudo unattended-upgrades --dry-run` or more verbose `sudo unattended-upgrades --dry-run --debug`

More details can be found [here](https://help.ubuntu.com/community/AutomaticSecurityUpdates).

### Enable firewall (UFW)

1. Install UFW

   ```bash
   sudo apt install ufw
   ```
2. Deny incoming traffic and allow outgoing

   ```bash
   sudo ufw default deny incoming
   sudo ufw default allow outgoing
   ```
3. Edit `/etc/default/ufw` and set `IPV6=no`.
4. Enable firewall and check results

   ```bash
   sudo ufw enable
   sudo ufw status verbose
   ```

### Disable IPv6

Usually when you are not aware that you need IPv6 it only provides additional attack surface.
Modify `/etc/default/grub` and ensure that it has `ipv6.disable=1` set. 

For example:

```
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash ipv6.disable=1"
GRUB_CMDLINE_LINUX="ipv6.disable=1"
```

Then run `sudo update-grub`.

### Encrypt drives

#### Operating system (LUKS)

The easiest solution is to encrypt OS partitions during installation. With Ubuntu, the minimum effort solution is
to select `use entire disk and set up encrypted LVM` during the OS installation.

#### External devices (LUKS or Veracrypt)

* For LUKS: https://mtask.github.io/2020/07/01/luks-encrypt-external-hdd.html 
* Veracypt: 

> VeraCrypt is a free open source disk encryption software for Windows, Mac OSX and Linux.  
> -- https://www.veracrypt.fr/en/Home.html

With Veracrypt, it's possible to create encrypted containers that are in practice just encrypted files which can be then mounted as drives. It can also be used to encrypt drives. The main use-case for me is multi-platform cases where I need to, for example, open the same encrypted files in Linux, OS X, and Windows.

### Configure logrotation

My idea here is to have (sys)logs retained for a month and then do backup of logs while doing backup of other things.

Edit `/etc/logrotate.d/rsyslog` and set:

```
/var/log/mail.info
/var/log/mail.warn
/var/log/mail.err
/var/log/mail.log
/var/log/daemon.log
/var/log/kern.log
/var/log/auth.log
/var/log/user.log
/var/log/lpr.log
/var/log/cron.log
/var/log/debug
/var/log/syslog
/var/log/messages
{
	rotate 30
	daily
	missingok
        su root syslog
	notifempty
	delaycompress
	compress
	postrotate
		/usr/lib/rsyslog/rsyslog-rotate
	endscript
}
```

Check also other configurations files under `/etc/logrotate.d/` and do some tuning when needed. Also, try to identify log files that do not have logrotate configuration, and then add one for important logs.

### Configure audit logging (auditd)

With an average workstation installation, I don't really assume that most of the people will actively monitor workstation audit logs or even be aware of such a thing.

However, if you do regular backups and have the capacity to backup your logs then setting up audit logging can be useful. For example, let's say that you notice something suspicious happening in your workstation then you may be able to figure out when something started to happen if you have stored X amount of old logs.

Below is a minimal example setup to get started with auditd:

1. Install auditd `sudo apt install auditd`

2. Copy stig rules and decompress `cp /usr/share/doc/auditd/examples/rules/30-stig.rules.gz /etc/audit/rules.d/ && gunzip /etc/audit/rules.d/30-stig.rules.gz`

3. Add rules for sudo events. Add file `/etc/audit/rules/10-custom.rules`

   ```
   # sudo events
   -a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=-1 -F key=sudo_log
   -a always,exit -F arch=b32 -S execve -F euid=0 -F auid>=1000 -F auid!=-1 -F key=sudo_log
   ```

4. (Re)start and enable auditd: `sudo systemctl restart auditd && sudo systemctl enable auditd`

5. Check status with `sudo auditctl -s` and rules with `sudo auditctl -l`

With the default configuration auditd will log events to `/var/log/audit/audit.log` and you can also use `ausearch` to analyze log files. 
For example: 

* `sudo ausearch -k sudo_log` would list all sudo events.
* `sudo ausearch -a 61761` would list all events related to audit id 61761.
* `sudo ausearch --input /mnt/stored-audit.log -k perm_mod` to serch from an alternative log file location (for example when checking events from backed up logs). 

### Harden kernel module configuration and sysctl parameters

Disable (usually) unnecessary file-systems (common [CIS benchmark](https://www.cisecurity.org/cis-benchmarks/) recommendations):

```bash
sudo bash -c "echo 'install cramfs /bin/true' > /etc/modprobe.d/cramfs.conf"
sudo bash -c "echo 'install freevxfs /bin/true' > /etc/modprobe.d/freevxfs.conf"
sudo bash -c "echo 'install jffs2 /bin/true' > /etc/modprobe.d/jffs2.conf"
sudo bash -c "echo 'install /bin/true' > /etc/modprobe.d/hfs.conf"
sudo bash -c "echo 'install hfsplus /bin/true' > /etc/modprobe.d/hfsplus.conf"
sudo bash -c "echo 'install udf /bin/true' > /etc/modprobe.d/udf.conf" 
```

Edit `/etc/sysctl.d/99-sysctl.conf` and add sysctl paramters:

```ini
fs.suid_dumpable=0
fs.protected_fifos=2
fs.protected_hardlinks=1
fs.protected_regular=2
fs.protected_symlinks=1
kernel.core_uses_pid=1
kernel.ctrl-alt-del=0
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
kernel.perf_event_paranoid=3
kernel.randomize_va_space=2
kernel.sysrq=0
kernel.unprivileged_bpf_disabled=1
kernel.yama.ptrace_scope=2
net.core.bpf_jit_harden=2
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.bootp_relay=0
net.ipv4.conf.all.forwarding=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.all.proxy_arp=0
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.default.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_timestamps=1
dev.tty.ldisc_autoload=0
```

Run `sudo sysctl -p` and use `sysctl -a` to check parameters or `sudo sysctl -a|grep <param>` to check for a specific parameter.

The above settings are pretty common recommendations. See [https://www.kernel.org/doc/Documentation/sysctl/](https://www.kernel.org/doc/Documentation/sysctl/) for sysctl documentation if you are interested in details.

If someone is wondering why there are no `net.ipv6.*` parameters on the list it's because we disabled the IPv6 support in a way that those parameters do not work anymore. 

### Restrict USB devices (usbguard)

> The USBGuard software framework helps to protect your computer against rogue USB devices (a.k.a. BadUSB) by implementing basic whitelisting and blacklisting capabilities based on device attri
> -- https://usbguard.github.io/

1. Install usbguard: `sudo apt install usbguard`
2. Connect USB devices that you know you need
3. Create initial policy: `sudo bash -c 'usbguard generate-policy > /etc/usbguard/rules.conf'`
4. Edit `/etc/usbguard/rules.conf` and remove internal stuff you don't need (e.g. camera)
5. Start and enable usbguard: `sudo systemctl start usbguard.service && sudo systemctl enable usbguard`

When you need to add a new device:
* Insert the device
* Run `'usbguard generate-policy`
* Search for the line for the new device
* Add the line to `/etc/usbguard/rules.conf`
* Restart usbguard: `systemctl restart usbguard.service`

### Take file hash snapshot of the system (AIDE)

> AIDE (Advanced Intrusion Detection Environment, [eyd]) is a file and directory integrity checker.
> What does it do?
> It creates a database from the regular expression rules that it finds from the config file(s). Once this database is initialized it can be used to verify the integrity of the files.
> -- https://aide.github.io/

1. Install AIDE: `sudo apt install aide`
2. Configure AIDE rules (small example only):
   ```
   #/etc/aide/aide.conf.d/10_aide_rules:
   
   /etc Full
   /usr/local/sbin Full
   /usr/local/bin Full
   /usr/sbin Full
   /usr/bin/sbin Full
   /bin Full
   /snap/bin Full
   ```
3. Run `sudo update-aide.conf`
4. Initialize AIDE database `sudo aide -i -c /var/lib/aide/aide.conf.autogenerated && sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db`
5. Copy `/var/lib/aide/aide.db` to some external media like encrypted USB drive.

Ideally, you would repeat steps 4 and 5 every time you update your system or change some critical configuration file (e.g. audit rules) or do something that causes a change in a critical file (e.g. change your password). Then you can compare the system against the latest copy if you realize that something weird might have happened on your system.

To check the filesystem against the AIDE database use command `sudo aide -C -c /var/lib/aide/aide.conf.autogenerated`. Ensure that in `/var/lib/aide/aide.conf.autogenerated` the `database=` setting is pointing to correct file when you have the database in some other location than `/var/lib/aide/aide.db`.
You can also edit the location to `/etc/aide/aide.conf` and re-run `sudo update-aide.conf` if you want to make the change permanent.

### Virus scanner (ClamAV)

ClamAV: [https://www.clamav.net/](https://www.clamav.net/)

* Install: `sudo apt-get install clamav clamav-daemon`
* Stop freshclam service for now: `sudo systemctl stop clamav-freshclam`
* Get new signatures: `sudo freshclam`
* Start freshclam service: `sudo systemctl start clamav-freshclam`
* Scan staff: `sudo clamscan --infected --recursive -v /home/`
* Automate with cron: `sudo crontab -e` -\> `0 23 * * * sudo /usr/bin/clamscan --remove --infected --recursive /home/`
* See other clamscan options with `man clamscan` and also check [On-Access Scanning](https://docs.clamav.net/manual/OnAccess.html)

### Auditing security configuration (Lynis)

One common tool for auditing security related configuration is [Lynis](https://cisofy.com/lynis/).
Install Lynis and run `sudo lynis audit system`. Note that many of the default checks are mainly for servers, so there can be some recommendations that do not work so well with workstation setups.

## Take backups

Below is some backup tools that I have usually used:

* Rsync (https://en.wikipedia.org/wiki/Rsync)
* Duplicity (http://duplicity.nongnu.org/features.html) 
* Rsnapshot (https://rsnapshot.org/) 

If you are not too familiar with these tools, a short description would be that Rsync is the de-facto tool for creating file-level backups, and many other tools like Rsnapshot adds "brains" on top of Rsync. Meaning things like automated incremental backups and rotation etc.
Despite the post [replace-rsnasphot-with-duplicity](https://mtask.github.io/2021/10/22/replace-rsnasphot-with-duplicity.html) I still recommend Rsnapshot as an excellent tool for incremental backups. Debian bullseye situation was just a small hiccup in its usage. Arch wiki has a good guide for setting up backups with Rsnapshot: [https://wiki.archlinux.org/title/Rsnapshot](https://wiki.archlinux.org/title/Rsnapshot).

If you need built-in encryption and/or signing features then duplicity is excellent choice. It uses GPG to sign and/or encrypt backups. Duplicity seems also like a good choice if you are planning to do cloud backups (S3, Google cloud) because it seems to have support for many cloud backends. 

If you just want a simple backup of your whole system and have some external drive with enough space then you can just use simple rsync command.

```
# mount your external device to /mnt
sudo mount /dev/<your-ext-device> /mnt
# crete directory with yyyymmdd format
sudo mkdir /mnt/$(date +%Y%m%d)
# copy the whole system (exclude things that usually should be ignored in this kind of backup)
sudo rsync -aAXv / --exclude={"/dev/*","/proc/*","/sys/*","/tmp/*","/run/*","/mnt/*","/media/*","/lost+found"} /mnt/$(date +%Y%m%d)
```

One way I use Rsnapshot to backup workstation is to have separate `rsnapshot.conf` file in my external SSD:

```
config_version	1.2
snapshot_root	/media/mtask/backup/rsnapshot/ # /media/mtask/backup is mount point for external drive 
cmd_cp		/bin/cp # Default rsnapshot.conf value
cmd_rm		/bin/rm # Default rsnapshot.conf value
cmd_rsync	/usr/bin/rsync # Default rsnapshot.conf value
cmd_logger	/usr/bin/logger # Default rsnapshot.conf value
retain	backup	30 # retain 30 backup snapshots
verbose		2 # Default rsnapshot.conf value
loglevel	3 # Default rsnapshot.conf value
lockfile	/var/run/rsnapshot.pid # Default rsnapshot.conf value
backup	/home/mtask/	localhost/ # Backup home directory
backup	/etc/		localhost/ # Backup /etc
backup	/usr/local/	localhost/ # Backup /usr/local
backup	/var/log/	localhost/ # Backup logs
```

Then I have `backup.sh` inside the same drive:

```bash
#!/bin/bash

mkdir -p rsnapshot
rsnapshot -c ./rsnapshot.conf -v backup
```

When I take a new backup I insert my external drive via USB, decrypt it, mount it to `/media/mtask/backup`, and launch the backup with command `cd /media/mtask/backup/ && sudo ./backup.sh`. This configuration retains thirty snapshots under `/media/mtask/backuprsnapshot/` directory.

Ubuntu also has a program called Déjà Dup pre-installed which is a GUI tool that uses duplicity behind the scenes. If you are more comfortable with GUI tools then this might be good choice for you. In Ubuntu you can find this by hitting the Windows key and searching for "Backups".

## Securing web browser (Firefox)

A web browser is most likely the most used software in an average workstation. It is also one of the most likely targets for an attack on a workstation. You accidentally browse some shady site, the site has malicious code that exploits a zero-day in your browser, and then your machine gets owned. 

This kind of attack surface we try to reduce with restrictive actions in this section. Restrictions methods I'm showing here are also applicable with other software but it does take some work to apply these controls to all software you use.

### Deploy Firefox settings policy

Firefox allows to configure it security (and other) features using JSON formatted policy file.

Below is an example policy to harden Firefox configuration. The files needs to be put under Firefox installation directory and this location varies per distribution (see: [https://support.mozilla.org/en-US/kb/managing-policies-linux-desktops](https://support.mozilla.org/en-US/kb/managing-policies-linux-desktops). For Ubuntu 20.04 this location is `/usr/lib/firefox/distribution/policies.json`:

```json
{
  "policies": {
    "BlockAboutConfig": true,
    "OfferToSaveLogins": false,
    "DontCheckDefaultBrowser": true,
    "AppAutoUpdate": false,
    "DisableSetDesktopBackground": true,
    "DisableAppUpdate": true,
    "DisableDeveloperTools": true,
    "DisableFeedbackCommands": true,
    "DisableFirefoxAccounts": true,
    "DisableFormHistory": true,
    "BlockAboutProfiles": true,
    "BlockAboutAddons": true,
    "BlockAboutSupport": true,
    "UserMessaging": {
      "WhatsNew": false,
      "ExtensionRecommendations": false,
      "FeatureRecommendations": false,
      "UrlbarInterventions": false
    },
    "DisableSecurityBypass": {
      "InvalidCertificate": true,
      "SafeBrowsing": true
    },
    "DisabledCiphers": {
      "TLS_AES_256_GCM_SHA384": false,
      "TLS_AES_128_GCM_SHA256": false,
      "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": false,
      "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": false,
      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": false,
      "TLS_DHE_RSA_WITH_AES_128_CBC_SHA": true,
      "TLS_DHE_RSA_WITH_AES_256_CBC_SHA": true,
      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": true,
      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": true,
      "TLS_RSA_WITH_AES_128_CBC_SHA": true,
      "TLS_RSA_WITH_AES_256_CBC_SHA": true,
      "TLS_RSA_WITH_3DES_EDE_CBC_SHA": true,
      "TLS_RSA_WITH_AES_128_GCM_SHA256": true,
      "TLS_RSA_WITH_AES_256_GCM_SHA384": true
    },
    "SSLVersionMin": "tls1.2",
    "SearchSuggestEnabled": false,
    "DisableTelemetry": true,
    "PasswordManagerEnabled": false,
    "SearchSuggestEnabled": false
  }
}
```

More information about policy settings:

* [https://support.mozilla.org/en-US/kb/customizing-firefox-using-policiesjson](https://support.mozilla.org/en-US/kb/customizing-firefox-using-policiesjson)
* [https://github.com/mozilla/policy-templates/blob/master/README.md](https://github.com/mozilla/policy-templates/blob/master/README.md)

If your policy doesn't seem to work:

* Go to `about:support` page in Firefox
* Check `Enterprise Policies` section and if it contains "Error" link
* Open the link and check `Policy Errors`


### Run web browser in sandbox (Firejail)

> **Firejail** is a SUID program that reduces the risk of security breaches by restricting the running environment of untrusted applications using [Linux namespaces](https://lwn.net/Articles/531114/) and [seccomp-bpf](https://l3net.wordpress.com/2015/04/13/firejail-seccomp-guide/).
>
> -- https://firejail.wordpress.com/

The main difference to Apparmor is that Apparmor  uses kernel features to restrict applications while Firejail is an userspace program that uses things like [Linux namespaces](https://en.wikipedia.org/wiki/Linux_namespaces) to isolate processes. 

* Install Firejail: `sudo apt install firejail`
* Run Firefox in sandox: `firejail firefox` (close existing firefox processes before this)

It's also possible (and highly recommendable) to use Firejail and Apparmor together.

Enable Apparmor profile for Firejail:

```bash
sudo aa-enforce firejail-default
firejail --apparmor firefox
```

**Note that now Firefox is restricted by Firejail sandboxing profile and by `firejail-default` Apparmor profile, but not by its own Apparmor profile even if it has one set.**
  
Remember to reload profile if you change it: `sudo apparmor_parser -r /etc/apparmor.d/firejail-default`.

Like with Apparmor, it of course is not only for web browsers, but you can use Firejail to sandbox other applications as well. Check `/etc/firejail/` for existing profiles for other applications.

When you have the jail working you most likely would like to launch this from Gnome's dock. You can do this by creating `~/.local/share/applications/jailfox.desktopt`:

```ini
[Desktop Entry]
Name=jailfox
Exec=firejail --private=/home/mtask/.jailfox --apparmor firefox
Icon=firefox
Type=Application
```

The setting `--private=/home/mtask/.jailfox` creates "virtual home folder" to that path for the process.

If you already have Firefox set as a favourite in your Gnome dock then remove it to avoid confusion. Hit the "Windows key" and search for "jailfox" and you should see Firefox icon with "jailfox" as an application name. Right click the icon and add it as favourite.


### Enable Apparmor profile for Firefox

(If you plan using Firejail with Firefox then skip this unless you have figured out a proper way to use Firefox's own profile with Firejail)

> AppArmor ("Application Armor") is a Linux kernel security module that allows the system administrator to restrict programs' capabilities with per-program profiles. Profiles can allow capabilities like network access, raw socket access, and the permission to read, write, or execute files on matching paths. AppArmor supplements the traditional Unix discretionary access control (DAC) model by providing mandatory access control (MAC). It has been partially included in the mainline Linux kernel since version 2.6.36 and its development has been supported by Canonical since 2009. 
> -- https://en.wikipedia.org/wiki/AppArmor

Ubuntu seems to have pre-defined apparmor profile for Firefox but it's disabled by default. You can find some other apparmor-profiles for Ubuntu [here](https://gitlab.com/apparmor/apparmor-profiles/-/tree/master/ubuntu/), and even if you are not using Ubuntu, you can use those as reference for creating own profiles. 

Remove the symlink to `/etc/apparmor.d/disable/` directory if it exists to remove profile's disabled status.

```
sudo unlink /etc/apparmor.d/disable/usr.bin.firefox
```

The profile allows full read access to `/` and many other places so things like `file:///` browsing would work. If you don't want to allow such a wide read access, then open the profile file and comment out the following sections:

```
  # allow access to documentation and other files the user may want to look
  # at in /usr and /opt
  #/usr/ r,
  #/usr/** r,
  #/opt/ r,
  #/opt/** r,

  # so browsing directories works
  #/ r,
  #/**/ r,
```

I also disabled access to `~/.ssh` and `~/Documents` by adding these lines to the profile:

```
deny @{HOME}/Documents rwx,
deny @{HOME}/.ssh rwx,
```

Reload the profile after changes:

```
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.firefox
```

You can now open Firefox and test `file:///` paths to verify that at least read restrictions work. Accessing `file:///home/<your user>/Downloads`  should work, but `file:///home/<your user>/Documents` should not work.

You can check logs with something like `sudo grep -r 'DENIED' /var/log/audit/|grep -i firefox` if you start having issues with Firefox. If needed, set profile to complain mode for a while (`sudo aa-complain firefox`),  run `sudo aa-logprof`, and finally enforce the profile again (`sudo aa-enforce firefox`). Be careful with aa-logprof to not to re-allow anything that you wanted to be denied and only tested to verify that deny rules work.

## Bonus tips

* **Password hygiene**: Use password manager like [KeePass](https://keepass.info/)
  - You can use cloud storage like Dropbox to share the KeePass database between different devices
* **Physical security**:
  - Cover your webcam
  - Set BIOS/UEFI password
* **Use Multi-factor authentication (MFA)**: Use Authentictor app like Microsoft Authenticator to enable MFA with different services.
* **Email encryption and signing**: Check [OpenPGP in Thunderbird](https://support.mozilla.org/en-US/kb/openpgp-thunderbird-howto-and-faq)
  - Check [Protonmail](https://protonmail.com/) if you can use online service and want more out-of-the-box experience
* **VPNs**:
  - Don't use free 3rd party VPNs (There ain't no such thing as a free lunch)
  - Ask yourself if you trust a 3rd party VPN more than the network you are connected to when you are planning to use VPN
  - Consider setting up your own VPN server with [OpenVPN](https://openvpn.net/) if you, for example, you are regularly connected to some other networks than your home network.
