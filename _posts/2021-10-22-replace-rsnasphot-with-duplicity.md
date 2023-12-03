---
title: 'Replacing Rsnapshot with Duplicity'
layout: 'post'
tags: ["Homelab"]
---
{:toc}

It seems that Rsnapshot has been dropped out from Debian Bullseye. I have been using Rsnapshot a lot for past five years and Debian is usually my server OS choice. So, this was an unpleasent suprise.

Based on the releated [Github issue](https://github.com/rsnapshot/rsnapshot/issues/279) discussions it seems like it's best to have some alternative even if installing Rsnapshot outside package manager would be possible.

I have usually had some setup like the one below to handle backups with my own servers.

![rsnapshot](/assets/rsnapshot-arch.png)

This way I have had local copies if I just accidentally delete some file or something, but also have remote versions in case there has been a bigger SHTF situation.



I show my first few attempts  with Duplicity in this post. After those attempts the latest versions will be found [here](https://github.com/mtask/duplicity-ansible) in format of Ansible role.




## First iteration

Duplicity offers encryption and signing using GPG but in the first iteration I only try to do local incremental backups and won't implement GPG features.

Below are sample files for daily backup setup. Every 30th backup is full backup (not incremental), incremental backups are stored for 1-6 full backups, and 12 full backups are stored.

The target structure per backup source is something like this:

```
full
  inc (daily)
  ...+29
full (about month)
  inc
  ...+29
full
  inc
  ...+29
full
  inc
  ...+29
full
  inc
  ...+29
full
  inc
  ...+29
full
full
full
full
full
full (about year)
```

### Wrapper script and configuration

* `/etc/backups/backup.config`:

This is a configuration file to specify source(s) and destination for backup.

```bash
sources=( "/etc/" "/opt/nginx/" )
destination="file:///srv/backups/"
```

* `/usr/local/sbin/backup.sh`:

This script is used to take backups with duplicity.

```bash
#!/bin/bash
## Remote backup script. Requires duplicity.

. /etc/backups/backup.config

# this check is mainly placeholder for now
# will maybe implement other destinations later
if  [[ "$destination" == file:///* ]]
then
  dest_local_path=${destination##file://} 
  echo $dest_local_path
  for src in "${sources[@]}"
  do
    full_dest="$dest_local_path"/"$src"
    echo $full_dest
    mkdir -p "$full_dest"
    duplicity --verbosity notice \
         --no-encryption \
         --full-if-older-than 30D \
         --num-retries 3 \
         --archive-dir /root/.cache/duplicity \
         --log-file /var/log/duplicity.log \
         "$src" "file://$full_dest"
    duplicity remove-all-but-n-full 12 --force "file://$full_dest"
    duplicity remove-all-inc-of-but-n-full 6 --force "file://$full_dest"
  done
fi
```

As far I have been able to understand duplicity expects one source directory. Meaning that in a case where I would like to backup `/etc/` and `/opt/nginx` I would need to set root (`/`) as source directory and exclude everything I don't want backup.

The script dynamically creates source directories' top-level structure to destination and uses those as actual destination directories. For example, with `sources=( "/etc/" "/opt/nginx/" )`, the end result is:

```
$ /usr/local/sbin/backup.sh
...
$ tree /srv/
/srv/
└── backups
    ├── etc
    │   ├── duplicity-full.20211022T155123Z.manifest
    │   ├── duplicity-full.20211022T155123Z.vol1.difftar.gz
    │   └── duplicity-full-signatures.20211022T155123Z.sigtar.gz
    └── opt
        └── nginx
            ├── duplicity-full.20211022T155123Z.manifest
            ├── duplicity-full.20211022T155123Z.vol1.difftar.gz
            └── duplicity-full-signatures.20211022T155123Z.sigtar.gz

4 directories, 6 files
```
Now I can seperately handle `/etc/` and `/opt/nginx/`backups:

```
# list files in /srv/backups/etc
duplicity list-current-files file:///srv/backups/etc

# list files in /srv/backups/etc/nginx
duplicity list-current-files file:///srv/backups/opt/nginx

# Restore /etc/passwd to /tmp/passwd
duplicity --file-to-restore passwd file:///srv/backups/etc/ /tmp/passwd --no-encryption
```

### Automation with systemd timer

This setup does not yet implement similar setup that I used to have with Rsnapshot. With Rsnapshot I usually implemented similar setup that can be found in [Arch Linux wiki](https://wiki.archlinux.org/title/Rsnapshot).

* `/etc/systemd/system/duplicity.service`:

This is systemd unit file that executes `backup.sh` script. 

```ini
[Unit]
Description=duplicity backups

[Service]
Type=oneshot
Nice=19
IOSchedulingClass=idle
ExecStart=/usr/local/sbin/backup.sh
```

* `/etc/systemd/system/duplicity.timer`:

This is timer that calls `duplicity.service` every day 05:30.

```ini
[Unit]
Description=duplicity daily backup

[Timer]
# 05:30 is the clock time when to start it
OnCalendar=05:30
Persistent=true
Unit=duplicity.service

[Install]
WantedBy=timers.target
```

## Second iteration

In second iteration I added support for (asymmetric) GPG encryption.

* `/etc/backups/backup.config`:

```bash
sources=( "/etc/" )
destination="file:///srv/backups/"
encrypt=1
gpg_homedir="/root/.backup_gpg"
gpg_encrypt_key="AEB4DF38A524CE433C2C37E87CA89DEC20476FBC"
```

When `encrypt=1` then `gpg_encrypt_key` is used to encrypt backups and `gpg_encrypt_key` needs to be imported to `gpg_homedir` and trusted.

Importing with `--homedir`:

```bash
gpg --homedir /root/.backup_gpg --import /root/enc.pub
```

* `/usr/local/sbin/backup.sh`:

```bash
#!/bin/bash
## Remote backup script. Requires duplicity.

. /etc/backups/backup.config

dest_local_path=${destination##*://} 
backend=${destination%://*}
echo $dest_local_path
for src in "${sources[@]}"
do
  full_dest="$dest_local_path"/"$src"
  echo $full_dest
  mkdir -p "$full_dest"
  if [[ "$encrypt" == 1 ]]
  then
      duplicity --gpg-options="--homedir=$gpg_homedir" --encrypt-key="$gpg_encrypt_key" \
           --verbosity notice \
           --full-if-older-than 30D \
           --num-retries 3 \
           --archive-dir /root/.cache/duplicity \
           --log-file /var/log/duplicity.log \
           "$src" "$backend://$full_dest"
      duplicity --gpg-options="--homedir=$gpg_homedir" --encrypt-key="$gpg_encrypt_key" remove-all-but-n-full 12 --force "$backend://$full_dest"
      duplicity --gpg-options="--homedir=$gpg_homedir" --encrypt-key="$gpg_encrypt_key" remove-all-inc-of-but-n-full 6 --force "$backend://$full_dest"
  else
      duplicity --verbosity notice \
           --no-encryption \
           --full-if-older-than 30D \
           --num-retries 3 \
           --archive-dir /root/.cache/duplicity \
           --log-file /var/log/duplicity.log \
           "$src" "$backend://$full_dest"
      duplicity remove-all-but-n-full 12 --force "$backend://$full_dest"
      duplicity remove-all-inc-of-but-n-full 6 --force "$backend://$full_dest"
  fi
done

```

The main difference with the previous iteration is `if [[ "$encrypt" == 1 ]]` check and seperate duplicity calls based on the result.

I also removed hard-coded `file://` backend references and now other backends like `scp://` or `sftp://` should work as long as ssh connection is configured to work with keys. This is configurable with the `destination=` setting.
