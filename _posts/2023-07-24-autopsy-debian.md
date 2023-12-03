---
title: 'Install Autopsy to Debian using Ansible'
layout: 'post'
tags: ["Security", "Ansible"]
---

**NOTE: This most likely won't lead to a perfectly working installation. There seem to be lots of issues with the Linux version at least in Autopsy 4.20.0. Check the issues section of this post before deciding if it's worth trying.**

I created a simple Ansible playbook that can install [Autopsy](https://www.autopsy.com/) on a local Debian installation.
There are still some issues with it (hence the note above) and based on my experience I would just go with the Windows version if you are trying to do any serious work.

## The playbook

Tasks in the playbook are pretty much same as defined in Autopsy's [installation guide for Linux](https://github.com/sleuthkit/autopsy/blob/develop/Running_Linux_OSX.md).
The playbook installs Autopsy to path `/opt/autopsy/autopsy-<autopsy version>/`.

Save the below playbook as `autopsy.yml` and then run `ansible-playbook autopsy.yml`

```yml
- hosts: localhost
  vars:
    autopsy_version: "4.20.0"
    autopsy_url: "https://github.com/sleuthkit/autopsy/releases/download/autopsy-{{ autopsy_version }}/autopsy-{{ autopsy_version }}.zip"
    sleuthkit_java_deb_url: "https://github.com/sleuthkit/sleuthkit/releases/download/sleuthkit-4.12.0/sleuthkit-java_4.12.0-1_amd64.deb"
  tasks:
  - name: Make installation directory
    file:
      path: /opt/autopsy
      state: directory
    become: yes

  - name: Download and install Sleuthkit Java deb
    apt:
      deb: "{{ sleuthkit_java_deb_url }}"
    become: yes

  - name: Check if autopsy directory already exists
    stat:
      path: /opt/autopsy/autopsy-4.20.0
    become: yes
    register: _autopsy_path

  - name: Check if autopsy zip already exists
    stat:
      path: /opt/autopsy.zip
    become: yes
    register: _autopsy_zip

  - name: Download autopsy zip
    get_url:
      url: "{{ autopsy_url }}"
      dest: /opt/autopsy.zip
    become: yes
    when: not _autopsy_zip.stat.exists

  - name: Unarchive autopsy
    unarchive:
      src: /opt/autopsy.zip
      dest: /opt/autopsy
    become: yes
    when: not _autopsy_path.stat.exists

  - name: Run prequisites script
    script: /opt/autopsy/autopsy-{{ autopsy_version }}/linux_macos_install_scripts/install_prereqs_ubuntu.sh
    become: yes

  - name: Install autopsy
    script: /opt/autopsy/autopsy-{{ autopsy_version }}/linux_macos_install_scripts/install_prereqs_ubuntu.sh
    become: yes
    
  - name: Get Java versions
    shell: "update-java-alternatives -l | grep java|grep -i bellsoft|awk '{print $3}'"
    become: yes
    register: _java

  - name: Install autopsy
    script: /opt/autopsy/autopsy-{{ autopsy_version }}/linux_macos_install_scripts/install_application.sh -i /opt/autopsy/autopsy-{{ autopsy_version }}/ -j "{{ _java.stdout }}"
    become: yes

  - name: Remove autopsy.zip
    file:
      state: absent
      path: /opt/autopsy.zip
    become: yes

  - name: Run autopsy
    debug:
      msg: "/opt/autopsy/autopsy-{{ autopsy_version }}/bin/autopsy --nosplash"
```


## Creating desktop launcher

Create file `.local/share/applications/autopsy.desktop` with the following content:

```ini
[Desktop Entry]
Name=Autopsy
Exec=/opt/autopsy/autopsy-4.20.0/bin/autopsy --nosplash
Terminal=false
Type=Application
Categories=System
```

This should bring up desktop launcher for the application.
I'm using `--nosplash` as I noticed that Autopsy can hide some initial pop-up window that requires hitting an "OK" button behind the splash screen and it can get stuck there.
When running as non-root you might want to ensure that you user has access to Autopsy's files (e.g. `sudo chown -R <user> /opt/autopsy/autopsy-4.20.0`.

Some operations may require root permissions, for example, giving a disk drive directly to Autopsy as a source data.
You might want to run Autopsy with sudo and add NOPASSWD entry for it, so it can still work via the desktop launcher.
Then just modify the desktop file's exec entry like this: `Exec=sudo /opt/autopsy/autopsy-4.20.0/bin/autopsy --nosplash`

Note that I was not able use local disk drives even as root, but adding a data source worked, for some reason, much better as root.

## Issues

As a summary of the below issues, this is what I did to make Autopsy somewhat working:

* Disabled Keyword Search (in GUI): `Tools`-\> `Plugins` -\> `Installed` -\> Select `KeywordSearch` -\> Deactivate.
* Disabled all ingest modules that cause error when adding a data source.
* Accepted the fact that I can't add local drives as data source, but image files still work.

### Solr server connection issue

I had an issue where Autopsy was not able to connect Solr server when creating a new case or starting an old one. This hanged Autopsy for a while until it continues without connection to the server.
I don't know if this a good way to "fix" this, but I was able to get pass the error by launching the server manually before starting Autopsy: `/opt/autopsy/autopsy/solr/bin/autopsy-solr start -p 23232 -force`.

In desktop file it's possible to do something like this:

```
[Desktop Entry]
Name=Autopsy
Exec=sudo bash -c '/opt/autopsy/autopsy-4.20.0/autopsy/solr/bin/solr start -p 23232 -force||true;/opt/autopsy/autopsy-4.20.0/bin/autopsy --nosplash'
Terminal=false
Type=Application
Categories=System
```

**Check the next issue before doing any of this**

### Out of memory (another Solr issue?)

When I added a data source I got `HeapDumpOnOutOfMemoryError` after a while and Autopsy crashed. 
I increased `Xmx` value in `/opt/autopsy/autopsy-4.20.0/etc/autopsy.conf`, but to me it seemed like there was some sort of memory bug.
It kept crashing with Xmx value of 8G and even adding a disk image of size 296M crashed the application. You may get pass this by adding more memory, but something still feels buggy here.

The issue seems to have something to do with Solr as I tested to not launch it manually, which means it did not start at all due to the other issue mentioned above, but now I did not get any memory errors.
After this Autopsy somewhat works, but considering all the issues, it doesn't really seem usable enough on Linux. 

To permanently disable Solr and Keyword search plugin go (in GUI) to `Tools`-\> `Plugins` -\> `Installed` -\> Select `KeywordSearch` -\> Deactivate. 
Now you don't have to wait for time out with Solr server connection.

### Detecting local drives

Autopsy did not detect local drives even when running as root.


### Unsupported ingest modules

There are some ingest modules, at least YARA and aLEAPP, that were not supported by the Linux version, but are still selected by default.
Autopsy gives an error about those when data source is added and doesn't start to process the data source properly if there were such errors.
Disable all ingest modules that are giving an error.
