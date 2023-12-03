---
title: 'Using Falco as Host Intrusion Detection System (HIDS)'
layout: 'post'
tags: ["Security"]
---
{:toc}

![falco in action](/assets/falco.gif)

> Falco is the open source standard for real-time detection of threats and anomalies across containers, Kubernetes, and cloud services.
> -- https://sysdig.com/opensource/falco/

Falco's real advantage over many other similar security solutions is its integration with container environments.
While its focus may be with containers it can also be used as HIDS solution with Linux hosts
and getting started with its usage is really easy. 

> You can think about falco as a mix between snort, ossec and strace.
> -- https://sysdig.com/blog/sysdig-falco/

You might want to check this post if you are not familiar with Falco, but are familiar with Auditd: [Falco vs. AuditD from the HIDS perspective](https://sysdig.com/blog/falco-vs-auditd-hids/)

## Installation 

Below is Falco's installation guide for Ubuntu/Debian at the time of writing.
You can check current installation instructions and instructions for different distributions from [here](https://falco.org/docs/getting-started/installation/#installing).

```sh
sudo curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | apt-key add -
echo "deb https://download.falco.org/packages/deb stable main" | sudo tee -a /etc/apt/sources.list.d/falcosecurity.list
sudo apt-get update -y
sudo apt-get -y install linux-headers-$(uname -r)
sudo apt-get install -y falco
```

Verify that Falco is running and enabled:

```sh
systemctl status falco
```

## Configuring rules

Falco uses YAML based syntax for rule definitions and rules can be spread between multiple files.

### Rules syntax

* Rules are set with `-rule:` definitions in rule files and have the following keys and options:

> rule: Name of the rule.  
> desc: Description of what the rule is filtering for.  
> condition: The logic statement that triggers a notification.  
> output: The message that will be shown in the notification.  
> priority: The “logging level” of the notification.  
> tags: Used to categorize rules. (optional)  
> enabled: Turn the rule on or off (optional, defaults to true)  
> -- https://sysdig.com/blog/getting-started-writing-falco-rules/

* Lists (`-list`) can be used to defined set of items (e.g. `denied_users`)
* Macros can be used to define reusable sub-sections of rules. (e.g. complex condition that is usable with multiple rules)
* Syntax and different options are explained in [here](https://falco.org/docs/rules/).
* Supported fields can be found [here](https://falco.org/docs/rules/supported-fields/).


### Rule files

Rule files are specified with `rules_file` variable in Falco's configuration file `/etc/falco/falco.yaml`. 
Comments give good instructions for the intended usage for different rule files.


```yaml
# File(s) or Directories containing Falco rules, loaded at startup.
# The name "rules_file" is only for backwards compatibility.
# If the entry is a file, it will be read directly. If the entry is a directory,
# every file in that directory will be read, in alphabetical order.
#
# falco_rules.yaml ships with the falco package and is overridden with
# every new software version. falco_rules.local.yaml is only created
# if it doesn't exist. If you want to customize the set of rules, add
# your customizations to falco_rules.local.yaml.
#
# The files will be read in the order presented here, so make sure if
# you have overrides they appear in later files.
rules_file:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/falco_rules.local.yaml
  - /etc/falco/rules.d
```


### Rule examples

You can find some examples here: [https://falco.org/docs/examples/](https://falco.org/docs/examples/).

#### SSH connections

Here's an example rule that warns about inbound and outbound ssh connections:

```yaml
# Not using user.name in inbound rule because it will grap sshd processe's user which might be confusing
# It would be ideal to get the actual user sshing in, but could not figure how to do this
- rule: Inbound SSH Connection
  desc: Detect Inbound SSH Connection
  condition: >
    ((evt.type in (accept,listen) and evt.dir=<) or
      (evt.type in (recvfrom,recvmsg))) and ssh_port
  output: >
    Inbound SSH connection (client_ip=%fd.cip client_port=%fd.cport server_ip=%fd.sip command=%proc.cmdline)
  priority: WARNING
  tags: [network]
- rule: Outbound SSH Connection
  desc: Detect Outbound SSH Connection
  condition: >
    ((evt.type = connect and evt.dir=<) or
      (evt.type in (sendto,sendmsg))) and ssh_port
  output: >
    Outbound SSH connection (user=%user.name server_ip=%fd.sip server_port=%fd.sport client_ip=%fd.cip command=%proc.cmdline)
  priority: WARNING
  tags: [network]
```

#### Netcat usage

Here's an example to detect netcat usage:


```yaml
- rule: Netcat Usage
  desc: Netcat Program Executed
  condition: >
    spawned_process and (proc.name = "nc" or proc.name = "nc.openbsd" or proc.name = "nc.traditional" or proc.name = "ncat")
  output: >
    Netcat execution detected (user=%user.name command=%proc.cmdline)
  priority: WARNING
  tags: [network]
```

#### Ping traffic

This example just captures all ping traffic. Note that it will generate an event per *sendto* and *recvmsg*. I couldn't figure out how to generate one alert per process causing suitable traffic. 
One way to limit number of events per process is to use `proc.duration < time_limit_in_nanoseconds` in condition.

```yaml
- rule: ping traffic
  desc: ping traffic
  condition: fd.l4proto = "icmp" and evt.type in (recvmsg,sendto)
  output: "ping traffic (client_ip=%fd.cip server_ip=%fd.sip command=%proc.cmdline fd_type=%fd.type cmdline=%proc.cmdline)"
  priority: DEBUG
  tags: [network]
```

I noticed that it sees only traffic initiated from the host itself. It does see both *sendto* and *recvmsg* when I launch ping on the host, but Falco doesn't generate any events when I pinged the host from an other host.
This might be Falco's limitation in its visibility to network traffic or design choice.

I also noticed a weird thing when I tried to capture IPv6 ping traffic. I'm not sure if this is some sort of bug or maybe I have gap in my IPv6 knowledge, but results seem weird:

```
19:53:01.238970442: Debug TEST (client_ip=fe80::a00:27ff:fe63:1f63 client_port=32 server_ip=fe80::a00:27ff:fe63:1f63 command=ping -6 -I eth1 fe80::a00:27ff:fe63:1f63 fd_type=ipv6 cmdline=ping -6 -I eth1 fe80::a00:27ff:fe63:1f63 l4proto=udp)
```

The command is clearly `ping -6`, `fd_type` is detected as `ipv6`, but `l4proto` is `udp`. 


#### Netwok tool usage

This example captures network related tooling usage that might be suspicious activity.

```yaml
- rule: Network Tool Usage
  desc: Network Tool Usage
  condition: spawned_process and network_tool_procs
  output: "network tool usage (user=%user.name parent=%proc.pname cmdline=%proc.cmdline pid=%proc.pid)"
  priority: WARNING
  tags: [network]
```

The `network_tool_procs` is specified in default rules file.

```yaml
- list: network_tool_binaries
  items: [nc, ncat, nmap, dig, tcpdump, tshark, ngrep, telnet, mitmproxy, socat, zmap]

- macro: network_tool_procs
  condition: (proc.name in (network_tool_binaries))
```

You can easily add other tools to the list by [appending](https://falco.org/docs/rules/#appending-to-lists-rules-and-macros) those to the `network_tool_binaries` list in your local rule file.

#### List example

An example list to specify users that should be allowed to uset Netcat without raising alerts.

```yaml
- list: user_allow_list_nc
  items: [vagrant, user2]
```

Then this list could be used in netcat detection rule's condition:

```yaml
  condition: >
    spawned_process and
      not user.name in (user_allow_list_nc) and
        (proc.name = "nc" or proc.name = "nc.openbsd" or proc.name = "nc.traditional" or proc.name = "ncat")
```

#### Macro example

An example macro to define condition for checking if user is root:
```yaml
- macro: user_is_root
  condition: user.uid = 0
```

Now you can reuse this macro in rules that should do something if user is or isn't root.

```yaml
condition: user_is_root
...
condition: not user_is_root
```

### Alert logging

Settings for alert outputs and formats are defined in `/etc/falco/falco.yaml`. You can specify a seperate event file by enabling the `file_output` variable. 

```yaml
file_output:
  enabled: true 
  keep_alive: false
  filename: ./events.txt
```

Note that the default filename path `./events.txt` will write events to `/events.txt` when Falco is running as a service, which ironically causes loop with one of the rules enabled by default:

```sh
08:16:24.978686614: Error File below / or /root opened for writing (user=root user_loginuid=-1 command=falco --pidfile=/var/run/falco.pid pid=8925 parent=systemd file=/events.txt program=falco container_id=host image=<NA>)
```

By default Falco logs alerts to syslog. You might want to disable this if you specify `file_output`:

```yaml
# Where security notifications should go.
# Multiple outputs can be enabled.

syslog_output:
  enabled: false
```

You can also log events in JSON format which can be ideal for further prosessing:

```yaml
# If "true", print falco alert messages and rules file
# loading/validation results as json, which allows for easier
# consumption by downstream programs. Default is "false".
json_output: true
```

An example event in JSON format:

```json
{
  "hostname": "logger",
  "output": "09:27:28.676255286: Warning Netcat execution detected (user=root command=nc.openbsd -l -p 9993)",
  "priority": "Warning",
  "rule": "Netcat Usage",
  "source": "syscall",
  "tags": [
    "network"
  ],
  "time": "2022-12-05T09:27:28.676255286Z",
  "output_fields": {
    "evt.time": 1670232448676255200,
    "proc.cmdline": "nc.openbsd -l -p 9993",
    "user.name": "root"
  }
}
```

Then there are also http and program outputs:

```yaml
# If keep_alive is set to true, the program will be started once and
# continuously written to, with each output message on its own
# line. If keep_alive is set to false, the program will be re-spawned
# for each output message.
#
# Also, the program will be closed and reopened if falco is signaled with
# SIGUSR1.
program_output:
  enabled: false
  keep_alive: false
  program: "jq '{text: .output}' | curl -d @- -X POST https://hooks.slack.com/services/XXX"

http_output:
  enabled: false
  url: http://some.url
  user_agent: "falcosecurity/falco"
```


Http output just sends the alert as is. 

```http
POST / HTTP/1.1
Host: 127.0.0.1:1234
User-Agent: falcosecurity/falco
Accept: */*
Content-Type: text/plain
Content-Length: 112

20:47:13.591701934: Warning Netcat execution detected (user=root command=nc.traditional -e /bin/bash -l -p 1111)
```

JSON example:

```http
POST / HTTP/1.1
Host: 127.0.0.1:1234
User-Agent: falcosecurity/falco
Accept: */*
Content-Type: application/json
Content-Length: 348

{"hostname":"logger","output":"20:52:24.150396379: Warning Netcat execution detected (user=vagrant command=nc -l -p 1234)","priority":"Warning","rule":"Netcat Usage","source":"syscall","tags":["network"],"time":"2022-12-05T20:52:24.150396379Z", "output_fields": {"evt.time":1670273544150396379,"proc.cmdline":"nc -l -p 1234","user.name":"vagrant"}}
```

This is a nice feature, but it's a bit limited. For example, you could send alerts directly to some external system like ticketing system, but usually you need to be able to modify content to specific format and maybe add/modify request's headers.

This limitation can be overcomed with the program output. You can send JSON formatted event to helper program which enriches the event. An example program could look something like this:

```python
#!/usr/bin/python3

import sys
import json
import requests

if sys.stdin.isatty():
   sys.exit("no input")
original_event = json.loads(sys.stdin.readlines()[0])
service_url = "http://127.0.0.1:1234"
extra_fields = {'example': 'extra'}
event = {**original_event, **extra_fields}

with open('/etc/falco/ticketing_token.txt') as f:
   bearer = f.read().replace('\n', '')

bearer = f"Bearer {bearer}"

headers = {'Authorization': bearer, 'User-Agent': 'falcosecurity/falco'}

requests.post(service_url, json=event, headers=headers)
```

Then `falco.yaml` configuration:

```yaml
program_output:
  enabled: true
  keep_alive: false
  program: "/opt/falco_helper.py"
```

Example output:

```http
POST / HTTP/1.1
Host: 127.0.0.1:1234
User-Agent: falcosecurity/falco
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Authorization: Bearer eyJxxx.xxx.xxx
Content-Length: 430
Content-Type: application/json

{"hostname": "logger", "output": "21:15:30.017658338: Warning Netcat execution detected (user=root command=nc.traditional -e /bin/bash -l -p 1111)", "priority": "Warning", "rule": "Netcat Usage", "source": "syscall", "tags": ["network"], "time": "2022-12-05T21:15:30.017658338Z", "output_fields": {"evt.time": 1670274930017658338, "proc.cmdline": "nc.traditional -e /bin/bash -l -p 1111", "user.name": "root"}, "example": "extra"}
```

## Addittional resources and notes

* Falco's documentation contains some tutorials and those can be found [here](https://falco.org/docs/tutorials/)
* [Detecting and alerting on anomalies in your container host with GitLab + Falco](https://about.gitlab.com/blog/2022/01/20/securing-the-container-host-with-falco/)
* Falco has its own webserver that can be used to query its status. If you don't use it, then you can disable it in `falco.yaml`:

```yaml
webserver:
  enabled: false
```


