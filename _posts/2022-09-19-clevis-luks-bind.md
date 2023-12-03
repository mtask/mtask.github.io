---
title: 'Binding LUKS encryption to TPM with Clevis'
layout: 'post'
tags: ["Security"]
---

{:toc}

This post somewhat continues the previous post where I showed how to steal LUKS encryption keys using tampered initramfs. That attack was possible because nothing verified that initramfs on the unencrypted boot partition has not been changed from the expected state.

One solution to avoid this type of situation is to bind the decryption of the disk with measurements of the boot components that are stored in TPM's PCR banks. I'll be using [Clevis](https://github.com/latchset/clevis) to seal the decryption key with TPM2 and bind the decrpytion with expected state of specified PCR banks. Overview of how Clevis does this can be found [here](https://github.com/latchset/clevis/blob/master/src/pins/tpm2/clevis-encrypt-tpm2.1.adoc#overview)

## How to know what is been measured?

You can use `tpm2_eventlog` to see what was measured during the boot and what PCRs those measurements extended.

```sh
tpm2_eventlog --eventlog-version=2 /sys/kernel/security/tpm0/binary_bios_measurements`
```

The `tpm2_eventlog` is part of the `tpm2-tools` package.

Here you can see, for example, that grub2 cmdline is stored in PCR8:

```yaml
- EventNum: 125
  PCRIndex: 8
  EventType: EV_IPL
  DigestCount: 2
  Digests:
  - AlgorithmId: sha1
    Digest: "6d5a7f5186d6bdba96b4a4cae22dbfa55696cdc1"
  - AlgorithmId: sha256
    Digest: "4362e6ac455ed2d2f378f9b5c19503f2afdbf4ae07e289500bbe13f2cd442a46"
  EventSize: 191
  Event:
    String: |-
      grub_cmd: linux /vmlinuz-5.15.0-47-generic root=/dev/mapper/vgubuntu-root ro ipv6.disable=1 apparmor=1 security=apparmor quiet splash ipv6.disable=1 apparmor=1 security=apparmor vt.handoff=7
```

## Installing Clevis

At least with Ubuntu and Debian you can install Clevis packages directly with `apt`.

```sh
sudo apt install clevis clevis-luks clevis-initramfs
```

This might be fixed with some version(s) of the clevis-initramfs, but I had to do this or initramfs hooks would not work.

```sh
# source: https://github.com/latchset/clevis/issues/236
mkdir -p /etc/initramfs-tools/scripts/local-top/
mkdir -p /etc/initramfs-tools/scripts/local-bottom/
mkdir -p /etc/initramfs-tools/hooks/
rsync -avz /usr/share/initramfs-tools/scripts/local-top/clevis /etc/initramfs-tools/scripts/local-top/
rsync -avz /usr/share/initramfs-tools/scripts/local-buttom/clevis /etc/initramfs-tools/scripts/local-buttom/
rsync -avz /usr/share/initramfs-tools/hooks/clevis /etc/initramfs-tools/hooks/
update-initramfs -u -k 'all'
```

Now you should reboot once to get the latest PCR values with PCR(s) that are affected by the initramfs update (PCR9 as far as I have seen).

## Clevis LUKS bind

When you have initramfs with Clevis hooks in place, you can then do Clevis bind operation with the luks encrypted disk. This does **not** remove existing keys from the disk and you should have at least one strong "break the glass" type of key. 

The below command binds decryption to PCR banks 1,7,8,9 and 14.

```sh
sudo clevis luks bind -d /dev/nvme0n1p3 tpm2 '{"pcr_ids":"1,7,8,9,14"}'
```

The LUKS encrypted device should be automatically deprycted after reboot assumming that no PCR value has changed. The user experience can be a bit funny as the boot will still prompt for the password, but the automatic decryption will kick-in after a few seconds. There's also no indication if Clevis failed, but this could be considered as a feature.

**Note that exactly same PCRs I selected might not be best for your installation. You should figure out what PCRs are best to bind to with your system.**

Easy way to test that PCR change prevents decryption is to update initramfs by launching `update-initramfs -u -k 'all'`. This should change PCR9 and prevent clevis from decrypting the disk during boot. This can also happen during system upgrades if the upgrade rebuilds initramfs. Another easy test is to disable secure boot if you had it enabled as it would change PCR7.

Now you have to use the "break the glass" key to decrypt the disk.

After this type of change you can fix the situation by unbinding and rebinding.

```sh
clevis luks  unbind -d /dev/nvme0n1p3 -s <slot number>
```

You can check the correct keyslot (`-s <slot number>`) with `cryptsetup luksDump /dev/nvme0n1p3`.

For example here the keyslot is **1**:

```yaml
Tokens:
  0: clevis
	Keyslot:    1
```

Then just do the rebind again:

```sh
sudo clevis luks bind -d /dev/nvme0n1p3 tpm2 '{"pcr_ids":"1,7,8,9,14"}'
```

