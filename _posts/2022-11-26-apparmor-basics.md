---
title: 'Apparmor basics'
layout: 'post'
tags: ["Security"]
---
{:toc}


In this post I show how to do some basic things with Apparmor profiles. 
At least modern Ubuntu and Debian distribution versions have Apparmor enabled by default, so there's no need for special preparations with those.
Check your distribution's documentation if you are running something else.
You may need to install `apparmor-utils` package to get some tools mentioned in this post.

Also note that not all distributions favor Apparmor as Mandatory Access Control (MAC) solution.
This might be a bit biased, due to the fact that I have professionally more experience with Debian based systems, but
compared to some MAC solutions (\*cough\*SELinux\*cough\*) it has much more shallow learning curve.

## Resources

Here are my favorite resources for creating Apparmor profiles:

* [OpenSUSE's documentation for profile syntax](https://doc.opensuse.org/documentation/leap/archive/42.3/security/html/book.security/cha.apparmor.profiles.html)
* [Ubuntu's man page for profile syntax](https://manpages.ubuntu.com/manpages/xenial/man5/apparmor.d.5.html)

## Tooling basics

* `aa-status`: List status of Apparmor profiles. Shows if profiles are in complain or enforce mode and which processes are confined by a profile.
* `aa-unconfined`: Shows unconfined processes. Use `--paranoid` option to scan all processes from /proc.
* `apparmor_parser`: Enable and disable profiles.
* `aa-genprof`/`aa-easyprof`/`aa-autodep`: Create profiles.
* `aa-logprof`: Improve profiles by scanning for denied actions.
* `aa-enforce`: Set profiles to enforce mode.
* `aa-complain`: Set profiles to complain mode.

There's also other tools available that are part of different Apparmor packages. You can check in your system what commands starting with `aa-` or `apparmor` are available. 

## Creating profile

Here I show how to create a profile for a simple python script. 
First, create a file that acts as a testing script.

```sh
sudo touch /opt/test.py
sudo chmod 755 /opt/test.py
```

Next, create the initial Apparmor profile for the script.

```sh
sudo bash -c 'aa-easyprof /opt/test.py > /etc/apparmor.d/opt.test.py'
sudo apparmor_parser -r /etc/apparmor.d/opt.test.py
sudo aa-complain /etc/apparmor.d/opt.test.py
```

The profile file should now look something like this:

```
# vim:syntax=apparmor
# AppArmor policy for test.py
# ###AUTHOR###
# ###COPYRIGHT###
# ###COMMENT###

#include <tunables/global>

# No template variables specified

/opt/test.py flags=(complain) {
  #include <abstractions/base>

  # No abstractions specified

  # No policy groups specified

  # No read paths specified

  # No write paths specified
}
```

The profile is basically empty apart from having some basic includes predefined. You can clean commented (`# ...`) lines, but note that `#include` lines are not comments.

One alternative for `aa-easyprof` is to use `aa-autodep` which tries to determine basic profile for the application. Usage is similar to `aa-easyprof `, but `aa-autodep` creates the profile file automatically, so you can just execute `sudo aa-autodep /opt/test.py`.

Open `/opt/test.py` for editing and add some read and write operations:

```py
#!/usr/bin/python3

with open('/tmp/test.txt', 'w+') as f:
   f.write("data")
```

Try executing `/opt/test.py`, and after that, run `sudo aa-logprof`. The `aa-logprof` scans the audit log for Apparmor *allowed* and *denied* events.

```
Updating AppArmor profiles in /etc/apparmor.d.
Reading log entries from /var/log/audit/audit.log.
Complain-mode changes:

Profile:  /opt/test.py
Path:     /usr/local/lib/python3.10/dist-packages/
New Mode: r
Severity: unknown

 [1 - include <abstractions/python>]
  2 - include <abstractions/totem>
  3 - /usr/local/lib/python3.10/dist-packages/ r,
(A)llow / [(D)eny] / (I)gnore / (G)lob / Glob with (E)xtension / (N)ew / Audi(t) / Abo(r)t / (F)inish

Profile:  /opt/test.py
Path:     /opt/test.py
New Mode: r
Severity: unknown

  1 - include <abstractions/totem>
 [2 - /opt/test.py r,]
(A)llow / [(D)eny] / (I)gnore / (G)lob / Glob with (E)xtension / (N)ew / Audi(t) / Abo(r)t / (F)inish

Profile:  /opt/test.py
Path:     /tmp/test.txt
New Mode: owner rw
Severity: unknown

  1 - include <abstractions/user-tmp>
 [2 - owner /tmp/test.txt rw,]
(A)llow / [(D)eny] / (I)gnore / (G)lob / Glob with (E)xtension / (N)ew / Audi(t) / (O)wner permissions off / Abo(r)t / (F)inish
```

Here I allowed the following things:

* Include abstraction `<abstractions/python>`
* Allow reading `/opt/test.py`
* Allow reading and writing to `/tmp/test.txt` if it's owned by the user.

Now, remove (`rm`) `/tmp/test.txt`. Set the profile to enforce mode with `sudo aa-enforce /opt/test.py` and verify that script still works by running it. You can use `sudo aa-status` to verify that the profile is in enforce mode. 

Next, modify `/opt/test.py` and add another open statement to open `/tmp/test2.txt`:

```py
#!/usr/bin/python3

with open('/tmp/test.txt', 'w+') as f:
   f.write("data")

with open('/tmp/test2.txt', 'w+') as f:
   f.write("data")
```


Running the script should give permission denied error like this:

```py
Traceback (most recent call last):
  File "/opt/test.py", line 3, in <module>
    with open('/tmp/test2.txt', 'w+') as f:
PermissionError: [Errno 13] Permission denied: '/tmp/test2.txt'
```

You could run `aa-logprof` and explicitly allow `/tmp/test2.txt` as well, but there are also other options. 
With need to open specifically these two files you can directly edit `/etc/apparmor.d/opt.test.py` and modify line `owner /tmp/test.txt rw,`:

```
owner /tmp/test{2,}.txt rw,
```

Reload the profile by running `sudo apparmor_parser -r /etc/apparmor.d/opt.test.py` and run `/opt/test.py`. 
The `{2,}` syntax allows both the `2` and empty string, comma works as a separator.


Next, let's try calling another program (ping) from the test script.
You need to have Apparmor profile for the ping command (`/etc/apparmor.d/bin.ping`). This may require installation of `apparmor-profiles` package and running `sudo aa-enforce /etc/apparmor.d/bin.ping`.

Add this to `test.py`:

```py
import subprocess

subprocess.call(["ping", "-c", "1", "127.0.0.1"])
```

Running the script should once again give permission error:

```py
PermissionError: [Errno 13] Permission denied: 'ping'
```

Running `sudo aa-logprof` will show:

```
Profile:  /opt/test.py
Execute:  /usr/bin/ping
Severity: unknown

(I)nherit / (C)hild / (P)rofile / (N)amed / (U)nconfined / (X) ix On / (D)eny / Abo(r)t / (F)inish

Should AppArmor sanitise the environment when
switching profiles?

Sanitising environment is more secure,
but some applications depend on the presence
of LD_PRELOAD or LD_LIBRARY_PATH.

[(Y)es] / (N)o
Enforce-mode changes:
```

Here I selected `P` for the first question and `N` for the second one because I had some issues if I selected to sanitize the environment. 
In addition to these, `aa-logprof` picked up bunch of other denied read and write operations. The final profile looks like this:

```
abi <abi/3.0>,

include <tunables/global>

/opt/test.py {
  include <abstractions/base>
  include <abstractions/python>

  /etc/apport/blacklist.d/ r,
  /etc/apport/blacklist.d/* r,
  /etc/apt/apt.conf.d/ r,
  /etc/default/apport r,
  /etc/group r,
  /etc/ssl/openssl.cnf r,
  /opt/ r,
  /opt/test.py r,
  /proc/sys/kernel/random/boot_id r,
  /run/systemd/userdb/ r,
  /run/systemd/userdb/* rw,
  /usr/bin/ping px,
  /usr/bin/python3.10 ix,
  /usr/share/dpkg/cputable r,
  owner /tmp/test{2,}.txt rw,
  owner /proc/*/fd/ r,
  owner /var/crash/_opt_test.py.*.crash rw,
}
```

Now, running the script should output the ping command's result:

```
$ /opt/test.py 
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.168 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.168/0.168/0.168/0.000 ms
```

This small example shows how creating Apparmor profiles is pretty much trial and error work. 
For some reason, running the program in complain mode does not always seem to catch everything needed.
Many times I have had to enable the enforce mode, execute the target application, run aa-logprof, and repeat until everything works.
There is also possibility that some state has changed where the application is doing some different things than during previous executions.

## Tips and tricks

Some tips when you can't figure out why a profile is not working and `aa-logprof` shows nothing:

* Your system might have some configuration where Apparmor events end up to some other log file than audit log. 
  * You can try `sudo grep -Pr 'apparmor="(ALLOWED|DENIED)"' /var/log/` to search for Apparmor events.
    * If events are found in `/var/log/syslog`, for example, you can then run `aa-logprof -f /var/log/syslog`. 
* If there are no Apparmor log events, then try to check application logs for hints, or use a debugging tool like strace.

When using readily available abstractions remember that you might allow more than you meant to if you don't check what the abstraction does. You can find abstractions in `/etc/apparmor.d/abstractions/` and manually check what each abstraction allows.

While Apparmor is deny by default there can still be situations where explicitly setting `deny` statements can be useful. Consider for example a directory path where everything expect one file should be readable by a program. You could then do something like this. 

```
/some/path/** r,
deny /some/path/some.file r,
```
