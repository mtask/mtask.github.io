---
title: 'Lock screen when USB device is not present or is removed (Linux)'
layout: 'post'
tags: ["Security"]
---

{:toc}

This post shows a sort of dead man's switch with an USB device. At least if you attach that USB device physically to yourself with something like key-chain cable.  Idea is to lock screen when a particular type of USB device is detached and prevent login (technically auto-logout) if expected USB device is not attached. So, something that is quite commonly seen with smart cards at least in Windows world.

I have tested this with Ubuntu 22.04.

## Locking screen when USB is removed

I'm using [https://en.wikipedia.org/wiki/Udev](udev) to detect "remove" event for the USB device to automatically lock screen when this happens.

The udev rule that detects the removed USB device is defined in `/etc/udev/rules.d/50-usb.rules`:

```
ACTION=="remove", SUBSYSTEM=="usb", ENV{PRODUCT}=="0000/0000/0000", RUN+="/usr/bin/sudo -u <your user> /usr/local/bin/usb-lock"
```

The "RUN+=" command is executed as root, so _sudo_ is only used to switch to your user's context. Replace `<your user>` with your actual username. You also need to replace `0000/0000/0000` with the actual "PRODUCT" value of your device. You find this by launching `udevadm monitor --propert` as root and then plug in your USB device.

The script `/usr/local/bin/usb-lock` that udev rule is executing looks like this:

```sh
#!/bin/bash

DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus notify-send "Alert" "Locking screen"
sleep 2
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus dbus-send --type=method_call --dest=org.gnome.ScreenSaver /org/gnome/ScreenSaver org.gnome.ScreenSaver.Lock
```

Remember to replace `1000`s with your user's UID. The script shows notification about screen being locked and locks the screen shortly after that. Clear limitation of this script currently is that it doesn't logout tty sessions, but it was not really relevant with my use-case. The login monitoring, that is explained later in this post, will monitor tty login sessions as well.

Ensure that only root can modify `/usr/local/bin/usb-lock`:

```sh
chown root:root /usr/local/bin/usb-lock && chmod 755 /usr/local/bin/usb-lock
```

For udev rules I'm using similar permissions that some existing rule files had:

```sh
chown root:root /etc/udev/rules.d/50-usb.rules && chmod 644 /etc/udev/rules.d/50-usb.rules
```

Finally, reload udev rules with command `sudo udevadm control --reload`.


## Logout if USB is not attached

I will be using [USBGuard](https://usbguard.github.io/)'s `list-devices` command to identify serial number of a particular device here. This is practical solution if you are already using USBGuard to determine what devices are allowed on your device. Other alternative could be to check output of `lsusb` command. What I'm doing here should work even if you don't have USBGuard rules enforced, so you don't have to use it to block anything.

The implementation I have checks the following scenarios:

* Existence of the expected USB when user logins to GNOME DE.
* Existence of the expected USB when user unlocks GNOME DE session.
* Existence of the expected USB when user logins to tty.

This is not some bulletproof security feature, but more like a nice additional hack on top of password login. All of these checks are done after the actual login, so it does not prevent testing password login, and some suitable action after login could prevent the USB based logout code from running. For example, if there's some magical key combination to prevent GNOME Startup Applications from running.

To actually use this as "_something you have_" type of MFA method, there should be some reliable hooks to run checks properly before password login, or even after, but checks should block further actions before user can get session. I might investigate thislater if GDM happens to have some suitable mechanism for this.

The below script (`/usr/local/bin/usbcheck`) does the actual checks for the expected USB device. Replace `xxx...` with your device's serial number. It could also be replaced with `$1` and then give serial number as an argument. Also change `/run/user/1000/bus` sections to match your user's ID.

You can get the serial number by running the `usbguard list-devices` command. You can compare two outputs, when device is attached and when it is not attached, if you are not sure which device is the one you are looking for.

```sh
#!/bin/bash

function check_usb() {
   if ! usbguard list-devices|grep -q 'serial "xxx..."'
   then
       echo "Expected USB device is not attached"
       if [[ $(tty) != "/dev/tty"* ]]
       then
           sleep 1
           DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus dbus-send --type=method_call --dest=org.gnome.ScreenSaver /org/gnome/ScreenSaver org.gnome.ScreenSaver.Lock
           sleep 1
       else
          # source calling the script should handle exit 1 as sign to logout e.g. in .bashrc
          exit 1
       fi
   fi
}

if [[ $(tty) != "/dev/tty"* ]]
then
    until [ -S /run/user/1000/bus ]
    do
        sleep 1
    done
    check_usb
    # if not in tty assume gnome session and monitor for screen unlock events
    # source: https://unix.stackexchange.com/questions/28181/how-to-run-a-script-on-screen-lock-unlock
    DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus dbus-monitor --session "type='signal',interface='org.gnome.ScreenSaver'" |
    while read x; do
        case "$x" in
            *"boolean false"*) check_usb;;
        esac
    done
else
   # if tty then just run check_usb
   check_usb
fi
```

I used GNOME's startup applications by creating a file `~/.config/autostart/usbceck.desktop` with needed parameters that script would run during logout. It also then seemed to kept running properly within the loop that reads `dbus-monitor` status.

```ini
[Desktop Entry]
Name=USBCHECK
GenericName=USBCHECK
Exec=/usr/local/bin/usbcheck
Terminal=false
Type=Application
X-GNOME-Autostart-enabled=true
```

More reliable and secure option could be to execute the script as systemd service, but executing things at suitable point after user login would most likely take some further digging. One potential solution might be to integrate the script with systemd's `user@<uid>.service` and from that it could maybe even be dynamically mapped to any user ID by passing the per instance UID as an parameter for the relevant script(s). That would maybe require script instance launch per user where each instance would monitor particular user or more logic to scripts, so those could handle multiple users.

For tty sessions I added the following to `.bashrc`:

```sh
if [[ $(tty) = "/dev/tty"* ]]
then
   if ! /usr/local/bin/usbcheck;then logout;fi
fi
```

Now USB checks should be done in the following situations:

* User logins to GNOME session
* User unlocks GNOME screensaver
* User logins to tty session
