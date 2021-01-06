---

title: 'Saving files from a (potentially) failing hard drive'
layout: 'post'
tags: ["Homelab"]

---

{:toc}

I recently helped a friend whose laptop had taken some physical damage, and the laptop's hard drive seemed to have some issues after that. 

This was a classic situation with important files on the disk and no backups. The disk included OS installation, so booting from it and copying files to an external device seemed a bit too risky. I then promised to try to back up the files carefully as it seemed that the disk and its content could be lost soon.

# Probe an image, not the disk

Like said, the state of the disk I had to work with was potentially unstable, so I wanted to minimize the need to work direct with it. 

First, I removed the disk from my friend's laptop and connected it to my laptop using a USB-SATA adapter. Then I took an image of the whole disk using GNU ddrescue.

```bash
sudo ddrescue /dev/sdb /srv/disk_image.raw /srv/log_file --try-again --force --verbose
```

To be honest, I'm not sure if these ddrescue options were optimal for this scenario, but at least I was able to copy the whole drive. See ddrescue's [man page](https://www.gnu.org/software/ddrescue/manual/ddrescue_manual.html) to see different options.

Next, I created a copy of the image to make sure that I don't need to try to create a new image if I screw something up.

```bash
sudo dd if=/srv/disk_image.raw of=/srv/disk_image.raw.original
```

# Find and mount the partition(s)

Now I had to find the partition where the needed data is, so I can mount it from the image, and try to copy all files in it.

Some command outputs in the below sections are not from the actual image I was working with, but as I'm writing this post afterward, I created a small dummy file to demonstrate these parts of the process.

## Find a partition

Listing partitions with `fdisk -l <image file>`:

```
$ sudo fdisk -l disk_image.raw
Disk disk_image.raw: 1000 MiB, 1048576000 bytes, 2048000 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x65a4907d

Device          Boot  Start     End Sectors  Size Id Type
disk_image.raw1        2048  817151  815104  398M  7 HPFS/NTFS/exFAT
disk_image.raw2      817152 2047999 1230848  601M  7 HPFS/NTFS/exFAT
```

Sometimes it might be clear which partition is the "target" and sometimes not. For this demonstration, with this dummy image file, let's just say that I knew that the second partition is the one which content I needed to access.

With the above information, it's possible to calculate the start sector of the targeted partition: `512*817152=418381824`.

## Mounting partitions from the disk image

The disk image file needs to be attached to a loop device, so it can be mounted as a block device. `losetup -a` can be used to check what loop devices already exist. `mknod` can be used to create a new loop device.

```
sudo mknod -m640 /dev/loop9 b 7 8
sudo losetup -o 418381824 /dev/loop9 disk_image.raw
sudo mount /dev/loop9 /mnt/
```

Notice that `-o 418381824` is the partition's start sector which I calculated previously. 

Now as I have the partition mounted I can just regularly copy files from the mountpoint with some tool like `rsync`:

```bash
rsync -vr /mnt/ /dest/path
```



# Some pointers

Even though I used a dummy image file in this post, the case with my friend's disk worked out the same way that there eventually were no issues while working with the disk and the image. If you have a case where the situation is not this good then you may want to check, for example, [TestDisk](https://www.cgsecurity.org/wiki/TestDisk) from CGSecurity.



When creating disk images, remember to verify that your destination has enough space for the image.


