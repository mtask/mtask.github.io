---
title: 'Encrypting an external HDD with LUKS'
layout: 'post'
tags: ["Security"]

---

{:toc}

A quick post to show how to encrypt an external hard drive using *Linux Unified Key Setup (LUKS)*. 


With "external" I mean a drive that doesn't include Operating System related partitions. 
It can be a portable one or an extra drive in your computer.



If you are looking for a solution with multi-platform support, then I would highly recommend checking the [VeraCrypt]([https://www.veracrypt.fr/en/Introduction.html) project.

# What is LUKS?

> The Linux Unified Key Setup (LUKS) is a disk encryption specification created by Clemens Fruhwirth in 2004 and was originally intended for Linux.
> 
> While most disk encryption software implements different, incompatible, and undocumented formats, LUKS implements a platform-independent standard on-disk format for use in various tools. This not only facilitates compatibility and interoperability among different programs, but also assures that they all implement password management in a secure and documented manner.
> 
> The reference implementation for LUKS operates on Linux and is based on an enhanced version of cryptsetup, using dm-crypt as the disk encryption backend. Under Microsoft Windows, LUKS-encrypted disks can be used with the now defunct FreeOTFE (formerly DoxBox, LibreCrypt). 
> 
> -- https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup

# Creating a partition

When I say that I will encrypt the disk I'm, of course, actually encrypting a partition on the disk. I will just create a one partition that will use the whole disk space.



I'm using a portable external HDD which is showing up as `/dev/sdb` in my system.

```
$ sudo fdisk -l /dev/sdb1 
Disk /dev/sdb1: 931,49 GiB, 1000169537536 bytes, 1953456128 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x00000000
```

I will use the `parted`tool to create the partition.

* Opening the drive with `parted`:

```
$ sudo parted /dev/sdb
```

* Creating a new partition table:

```
(parted) mklabel msdos
```

* Creating a new partition: 

```
(parted) mkpart primary
File system type?  [ext2]? ext4                                           
Start? 0                                                                  
End? 1000171                                                              
Warning: The resulting partition is not properly aligned for best performance: 1s % 2048s != 0s
Ignore/Cancel? Ignore                                                     
```

Parted command `unit MB print free` can be used to check the END value for the partition when the whole disk space is being used.

* Let's check the result and exit from parted:

```
(parted) print                                                            
Model: WD (scsi)
Disk /dev/sdb: 1000171MB
Sector size (logical/physical): 512B/512B
Partition Table: msdos
Disk Flags: 

Number  Start   End        Size       Type     File system  Flags
 1      0,00MB  1000171MB  1000171MB  primary  ext4         lba

(parted) quit
```

# Encrypting the new partition

The command to encrypt a partition is `cryptsetup luksFormat /dev/<partition>`. Now I just apply this against the `/dev/sdb1`: 

```
$ sudo cryptsetup luksFormat /dev/sdb1

WARNING!
========
This will overwrite data on /dev/sdb1 irrevocably.

Are you sure? (Type uppercase yes): YES
Enter passphrase for /dev/sdb1: 
Verify passphrase: 
$
```

# Create a filesystem on the encrypted partition

The encrypted partition needs to be opened using `cryptsetup luksOpen /dev/<partition`:

```
$ sudo cryptsetup luksOpen /dev/sdb1 encrypted-external-drive
Enter passphrase for /dev/sdb1: 
$
```

Now, to create the filesystem I can regularly use `mkfs.ext4`. But, instead of using it against `/dev/sdb1`, I need to use `/dev/mapper/encrypted-external-drive` which was specified during the `luksOpen` command.

```
$ sudo mkfs.ext4 /dev/mapper/encrypted-external-drive
mke2fs 1.45.5 (07-Jan-2020)
Creating filesystem with 244178175 4k blocks and 61046784 inodes
Filesystem UUID: b1sc17f2-e2e5-4baa-ba87-60a507bdd0b1
Superblock backups stored on blocks: 
    32768, 98304, 163840, 229376, 294912, 819200, 884736, 1605632, 2654208, 
    4096000, 7962624, 11239424, 20480000, 23887872, 71663616, 78675968, 
    102400000, 214990848

Allocating group tables: done                            
Writing inode tables: done                            
Creating journal (262144 blocks): done
Writing superblocks and filesystem accounting information: done     

$
```

To close the partition I will use `cryptsetup luksClose` command:

```
$ sudo cryptsetup luksClose /dev/mapper/encrypted-external-drive
$
```

# Mounting the encrypted partition

First, once again, the LUKS partition needs to be opened using `cryptsetup luksOpen`:

```
$ sudo cryptsetup luksOpen /dev/sdb1 encrypted-external-drive
Enter passphrase for /dev/sdb1:
$
```

The `/dev/mapper/<name I specified in luksOpen command>` can be now mounted like an any regular partition:

```
$ sudo mount /dev/mapper/encrypted-external-drive /mnt/
$ mount | grep 'encrypted-external'
/dev/mapper/encrypted-external-drive on /mnt type ext4 (rw,relatime)
$
```

Then, just a quick test to verify that files can be stored as expected:

```
$ sudo touch /mnt/test.txt
$ sudo umount /mnt 
$ sudo cryptsetup luksClose /dev/mapper/encrypted-external-drive
$ sudo cryptsetup luksOpen /dev/sdb1 encrypted-external-drive
Enter passphrase for /dev/sdb1: 
$ sudo mount /dev/mapper/encrypted-external-drive /mnt/
$ ls -la /mnt/
total 24
drwxr-xr-x  3 root root  4096 heinä   1 11:43 .
drwxr-xr-x 20 root root  4096 kesä   30 14:00 ..
drwx------  2 root root 16384 heinä   1 11:34 lost+found
-rw-r--r--  1 root root     0 heinä   1 11:43 test.txt
$
```
