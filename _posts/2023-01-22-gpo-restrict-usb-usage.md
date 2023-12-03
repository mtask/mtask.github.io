---
title: 'Restrict USB usage with Group Policy'
layout: 'post'
tags: ["Security"]
---
{:toc}

This short post shows some examples with Removable Storage Access policies in Windows. I'm using non domain joined Windows 10 machine for testing.
You can open Local Group Policy editor by typing `gpedit.msc` in Windows search bar. 

The relevant GPO settings are in path: `Computer Configuration > Administrative Templates > System > Removable Storage Access`.
These policies cover different type of removable devices as you can see from the picture below. I'm mainly testing USB storage drives which are controller by *Removable Disks* settings.

![GPO options](/assets/usb-gpo.png)

I'm using Putty's standalone binary to test execution rules. First thing I tested was setting *Removable Disks: Deny execute access*. 
I could still execute Putty, even after `gpupdate /force`, but after reboot I got this:

![Putty execute test](/assets/usb-putty-exec-test.png)

You need to be aware of different limitations this setting has. Denying execute on USB drive doesn't prevent from copying the binary to somewhere under `C:` drive and executing it from there.
Another big disadvantege on this setting is that it doesn't prevent link (`.lnk`) file execution. 
With a malicious link file, and some social engineering, it could be quite easy to trick someone to execute something like malicious powershell commands.
For example, the file could have Word icon, but it's actually a shortcut to something like this `powershell.exe -encodedCommand <base64 encoded commands>`.
  
Denying read access didn't only block read of the contents, but the device itself, so it seems to make the drive unusable in practice. If this is wanted then I would just set *deny* to all options.

Blocking write access works as one could expect. You can't write to any existing object or create new objects under the drive. You also can't delete anything from the drive. 
It's still possibly to copy objects as that doesn't modify the drive itself.

![write denied](/assets/write-denied.png)

To have more fine-grained options for preventing specific type of devices you need to use Device Installation policies. 
You can learn more about this from here: [https://learn.microsoft.com/en-us/windows/client-management/manage-device-installation-with-group-policy](https://learn.microsoft.com/en-us/windows/client-management/manage-device-installation-with-group-policy)
