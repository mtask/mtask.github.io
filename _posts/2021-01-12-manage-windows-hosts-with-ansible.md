---

title: 'Manage domain-joined Windows machines with Ansible'
layout: 'post'
tags: ["Windows", "Security", "Ansible"]

---

{:toc}

This post shows how to configure a domain-joined Windows machine to be managed with Ansible.

Ansible uses Windows Remote Management (WinRM) service to communicate with Windows machines. I Will use a domain with one member machine to deploy the WinRM service with a GPO and then configure the Ansible controller to use Kerberos authentication.



![image-20210112150034053](/assets/image-20210112150034053.png)

I have also included some testing steps before the final Kerberos and WinRM over HTTPS configuration, so it's easier to spot what's wrong in case of an issue.

## Deploy WinRM service with GPO

1. Create a new GPO or edit existing one depending on your GPO strategy.

2. Open the GPO and go to `Computer Configuration > Policies > Administrative Templates > Windows Components > Windows Remote Management (WinRM) > WinRM Service`

3. Open the setting `Allow remote server management through WinRM`

4. Set setting to enabled and set IPv(4|6) filtering TBD

   ![image-20210112101632279](/assets/image-20210112101632279.png)

   * I will also set `Allow basic authentication` and `Allow unencrypted traffic` to `enabled` for the first tests . Note that these are not needed if you only want to user Kerberos authentication with Ansible and/or do not want to test the configuration without HTTPS.

5. Go to `Go to Computer Configuration > Preferences > Control Panel Settings`

6. Right click the `service` and select `New > Service `

7. Select `...` next to the `Service name` and select the `WinRM ` service

   ![image-20210112120516929](/assets/image-20210112120516929.png)

8. Set the `Startup` to `Automatic (Delayed Start)`  and `Service action` to `Start service` and click `OK`

   ![image-20210112120722920](/assets/image-20210112120722920.png)

9. Save the GPO, go to a machine that gets settings from it, and run `gpudate /force` command.

10. Run the `Test-WSMan` cmdlet in Powershell to verify that WinRM  service is running.



## Testing the WinRM  connection with Powershell

From a machine in your domain run `Enter-PSSession <machine with WIRM running>`. I f you need to specify credentials for the connection then you can use something like this:

```powershell
$creds = Get-Credential
Enter-pssession <your machine> –credential $creds
```

![image-20210112122739023](/assets/image-20210112122739023.png)

![image-20210112122847949](/assets/image-20210112122847949.png)

Note that you will need to allow input traffic to ports 5985/TCP (HTTP) and 5986/TCP (HTTPS). You can later deny HTTP access when HTTPS is configured.

## First Ansible test

Now you need to have a Linux machine with Ansible installed. I have a Debian machine where I install Ansible using Pip3. 

1. Install ansible using pip3 and run it inside a virtual environment:

```
sudo apt install python3-venv python3-pip
python3 -m venv ansible
source ansible/bin/activate
pip3 install ansible "pywinrm>=0.3.0"
# Check ansible documentation for the recommended pywinrm version:
# https://docs.ansible.com/ansible/latest/user_guide/windows_winrm.html
```

2. Create a project structure: `mkdir -p win-test/inventory && touch win-test/inventory/hosts`

3. Add the below content to the `hosts` file and change your Windows host's IP, credentials and also inventory names if you want.

```ini
[win]
win101 ansible_host=<ip or dns name here>

[win:vars]
ansible_user='<username>'
ansible_password='<password here - hint, use ansible vault>'
ansible_connection=winrm
ansible_winrm_transport=basic
ansible_port=5985 # http - defaults to https 5986
```

4. Try the connection with `ansible -i inventory/hosts -m win_ping win101`. You should get response like this:

   ```json
   win101 | SUCCESS => {
       "changed": false,
       "ping": "pong"
   }
   ```

If you get some errors like `"basic: the specified credentials were rejected by the server` then check your WinRM  configuration on the windows host using `winrm get winrm/config` command and verify that all settings are applied in the way they were specified with the GPO. Note that each setting specified with a GPO should have statement `[Source="GPO"]`.

## Certificate enrollment

I'm using Windows Certificate Authority to auto-enroll a Computer certificate for the member machine. I'm not going through the CA deployment, but I have not done any special configurations for this. 

The next steps assume that the CA service is available.

1. Create a new GPO or edit existing one depending on your GPO strategy.

2. Navigate to `Computer Configuration > Policies > Windows Settings > Security Settings > Public Key Policies`

3. Open `Certificate Services Client – Auto-Enrollment` and set the setting to `Enabled` and check the first two settings

   ![image-20210112143306258](/assets/image-20210112143306258.png)

4. Click `OK` and right click `Automatic Certificate Request Settings > New > Automatic Certificate Request ...`

   * Certificate template:  `Computer` (or if you have another template then use that here)

   * Open `Automatic Certificate Request Settings` and ensure that you can see your template there.

     ![image-20210112143704676](/assets/image-20210112143704676.png)

5. Ensure that the GPO is linked to a correct OU and go to your member machine and run `gpudate /force`

6. Go to your Certificate Authority and ensure that you can see the issued certificate

   ![image-20210112144348158](/assets/image-20210112144348158.png)

7. In your member machine, create a WinRM HTTPS listener using the command `winrm quickconfig -transport:https` and verify listeners using `winrm enumerate winrm/config/listener`

## Ansible test with HTTPS

1. Export your CAs root certificate. 
   * In the CA server you can run the command `certutil -ca.cert win_ca.crt` to export the certificate.
2. In ansible controller, create a directory `files` on the same directory level with the inventory and copy the certificate to there.
3. Add `ansible_winrm_ca_trust_path=files/win_ca.crt` to the `hosts`.
4. Ensure that `ansible_host` variable is now using domain name that matches with the subject of your member machine's certificate and remember that your controller machine needs to be able to resolve the domain name.
5. Update `ansible_port` to `5986` in `inventory/hosts` and run `ansible -i inventory/hosts -m win_ping win101`. The expected result is the same as with HTTP connection.

It is possible to bypass certificate checks with the setting `ansible_winrm_server_cert_validation=ignore`. Do **not** use this setting in the production, but in case you have troubles to make the setup work, then this may be a valid test for troubleshooting.

The `hosts` file should now look something like this:

```ini
[win]
win101 ansible_host=<host>.<domain>

[win:vars]
ansible_user='<user>'
ansible_password='<password>'
ansible_connection=winrm
ansible_winrm_transport=basic
ansible_port=5986 # https
ansible_winrm_ca_trust_path=files/win_ca.crt
```

Now you can try the `ansible -i inventory/hosts -m win_ping win101` command again. You can also try some arbitrary command with `win_shell` module. For example: `ansible -i inventory/hosts -m win_shell -a "whoami" win101`.

I'm not including any playbook examples as there really isn't anything Windows specific with those except that Ansible's Windows modules are mostly used. You can found list of Windows modules here: [https://docs.ansible.com/ansible/2.9/modules/list_of_windows_modules.html](https://docs.ansible.com/ansible/2.9/modules/list_of_windows_modules.html)


## Kerberos authentication with ansible

I will create a domain user "ansible" and add that user to member machine's local administrators group using GPO. Then I will configure Kerberos authentication for that user.

2. Create a new domain user "ansible"

   ![image-20210112154933885](/assets/image-20210112154933885.png)

2. Create a new GPO or edit existing one depending on your GPO strategy

3. Open `Computer Configuration > Preferences > Control Panel Settings > Local Users and Groups`

5. Right click , select `New > Local Group` and `Update` the `Administrators (built-in)` group to include the `ansible` user.

   ![image-20210112155708589](/assets/image-20210112155708589.png)

6. Press `OK` to save the settings

6. Install Kerberos dependencies on the ansible controller

   ```
   sudo apt-get install python3-dev libkrb5-dev krb5-user
   pip3 install pywinrm[kerberos]
   ```

7. Edit `/etc/krb5.conf` on the controller machine and configure realm settings to match your domain:

   ```ini
   [libdefaults]
           default_realm = TOIMIALUE.LOCAL
           dns_lookup_realm = true
           dns_lookup_kdc = true
   [realms]
           TOIMIALUE.LOCAL = {
                   kdc = DC1.TOIMIALUE.LOCAL
   
           }
   [domain_realm]
           .toimialue.local = TOIMIALUE.LOCAL
           toimialue.local = TOIMIALUE.LOCAL
   ```

8. Change your `inventory/hosts` like this:

   ```ini
   [win]
   win101 ansible_host=win101.toimialue.local
   
   [win:vars]
   ansible_user=ansible@TOIMIALUE.LOCAL
   ansible_password='<password>'
   ansible_connection=winrm
   ansible_winrm_transport=kerberos
   ansible_port=5986 # https
   ansible_winrm_ca_trust_path=files/win_ca.crt
   ansible_winrm_kinit_mode=managed
   ```

   * Note that in the `ansible_user` value the domain needs to be uppercase like in my example.

Now you should be able to use Ansible with Kerberos as we have the target architecture up and running. You should now set settings `Allow basic authentication` and `Allow unencrypted traffic` to disabled in the GPO where you defined those settings.

## Additional security considerations

There are lots of different configuration options for things like authentication and transport security. I try to gather some additional security tips to this section. In minimum I would recommend to read [this](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/winrmsecurity?view=powershell-7.1) document from Microsoft. 

### Protect ansible user with Protected Users group

When a user is added to built-in `Protected User` group the user automatically gets some extra protection. It can be a good idea to add the created "ansible" user to this group.

![](/assets/winrm-ansible-protected-users.png)

[Microsoft's documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) specify the following protections:



> When the signed in user is a member of the Protected Users group the following protections are applied:
>
> - Credential delegation (CredSSP) will not cache the user's plain text credentials even when the **Allow delegating default credentials** Group Policy setting is enabled.
> - Beginning with Windows 8.1 and Windows Server 2012 R2, Windows Digest will not cache the user's plain text credentials even when Windows Digest is enabled.
> - NTLM will not cache the user's plain text credentials or NT one-way function (NTOWF).
> - Kerberos will no longer create DES or RC4 keys. Also it will not cache the user's plain text credentials or long-term keys after the initial TGT is acquired.
> - A cached verifier is not created at sign-in or unlock, so offline sign-in is no longer supported.
>
> ...
>
> Accounts that are members of the Protected Users group that authenticate to a Windows Server 2012 R2 domain are unable to:
>
> - Authenticate with NTLM authentication.
> - Use DES or RC4 encryption types in Kerberos pre-authentication.
> - Be delegated with unconstrained or constrained delegation.
> - Renew the Kerberos TGTs beyond the initial four-hour lifetime.



Easy way to test if the group is doing something is to RDP to some member machine using the "ansible" account. You should get this kind of response:

![](/assets/winrm-ansible-protected-users-rdp.png)

The RDP connection is not anymore possible with this user due to the restrictions with CredSSP. Ansible connection still works with Kerberos authentication. However, I have not done excessive testing for Ansible's different Windows modules while the ansible user is in Protected Users group.

### Unencrypted does not mean HTTP with WinRM

Something that might be a bit confusing is WinRM's HTTP(s) listeners and `Allow unencrypted traffic` setting. One could thing that unencrypted means HTTP, but this is not the case. The way I understands this is that the unencrypted communication means an authentication method which does not provide message-level encryption inside the transport layer.

You can test this by changing the `ansible_port` setting to `5985 (HTTP)` while having the `Allow unencrypted traffic` disabled. The connection should still works fine when Kerberos authentication is being used.

If you checked [this](https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/winrmsecurity?view=powershell-7.1) document, that I mentioned before, you have seen the following statement:

> It is helpful to consider the security of a PowerShell Remoting connection from two perspectives: initial authentication, and ongoing communication.
>
> Regardless of the transport protocol used (HTTP or HTTPS), WinRM always encrypts all PowerShell remoting communication after initial authentication.
>
> ...
>
> When connecting over HTTP, message-level encryption is determined by initial authentication protocol used.
>
> - Basic authentication provide no encryption.
> - NTLM authentication uses an RC4 cipher with a 128-bit key.
> - Kerberos authentication encryption is determined by the `etype` in the TGS ticket. This is AES-256 on modern systems.
> - CredSSP encryption is uses the TLS cipher suite that was negotiated in the handshake.

[Ansible's documentation](https://docs.ansible.com/ansible/latest/user_guide/windows_winrm.html#authentication-options) provides this kind of table regarding this:

| Option      | Local Accounts | Active Directory Accounts | Credential Delegation | HTTP Encryption |
| ----------- | -------------- | ------------------------- | --------------------- | --------------- |
| Basic       | Yes            | No                        | No                    | No              |
| Certificate | Yes            | No                        | No                    | No              |
| Kerberos    | No             | Yes                       | Yes                   | Yes             |
| NTLM        | Yes            | Yes                       | No                    | Yes             |
| CredSSP     | Yes            | Yes                       | Yes                   | Yes             |

So, even though I configured the HTTPS listener, it might be overkill with Kerberos authentication. However, as one can guess, the HTTP protocol itself is plaintext while the body is encrypted. Below is an example of traffic from Ansible play.

![](/assets/winrm-ansible-http.png)

I just want to point out that in a man-in-the-middle attack scenario, there is more attack surface. With suitable vulnerability in WinRM service or client (pywinrm), HTTPS can provide a needed extra security layer.

### Allow only required logon methods

You should explicitly specify which logon methods are allowed for the Ansible user as additional protection against lateral movement.

You can directly deny different logon methods with policies under "Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment". 

![](/assets/winrm-ansible-allowed-logons.png)

The one method you need to allow for the user is to login through the network. Other requirements may come depending on your use-cases.


### Prevent lateral movement inside domain network

Having the ability to manage AD machines with Ansible has its advantages, but the downside with security is that you have to allow an additional remote access method (WinRM). 

You also need a user with high-privileges on the managed systems. How high-privileged depends on your use-cases, but usually at least local administrator rights on the managed machines.

One mitigation against these threats is network filtering between hosts in the domain network. Usually, this means filtering in host firewalls of member machines.

Enabling WinRM creates default firewall rules where access is allowed from private networks and denied from public networks. Meaning that an attacker who has gained an initial foothold on your network and has credentials with permission to use WinRM can move laterally between hosts.

You should explicitly set firewall rules that restrict WinRM access only to necessary hosts. If you are only using it for Ansible, then allow access only from the Ansible controller.

![](/assets/winrm-ansible-firewall.png)


### Protect controller machine

The Ansible controller machine can be a very lucrative target for attackers. It usually provides high-privilege access to multiple machines and can contain secrets like user credentials.

There's no official solution of where and how to implement the Ansible controller. It can be a separate server or a system administrator's laptop, but the machine has to run some UNIX based operating system. Ansible project does not support Windows machines as a controller.

I prefer a separate server that can be better isolated and monitored than, for example, sysadmin laptops. One solution is to have a separate network segment for the controller where all traffic would go through a firewall. In the use-case of this post, an example architecture could like one in the below picture.

![](/assets/winrm-ansible-segmentation.png)

For secret-management, Ansible provides a solution called Ansible vault. It allows you to encrypt files and in-line strings. This way, there's no need to store secrets in plaintext.

### Tier model for priviliged access

When planning the access for Ansible in your domain environment, you should plan the privilege model in the same way you would do with a human administrator.

I have only shown examples with one controller machine and one user account to run Ansible on member machines. However, it may not be the best option if you want to manage the whole Active Directory environment with Ansible.

If you only want to manage, for example, a few servers with similar security requirements, then it does make sense to have one account for this, which is only allowed to access those specific servers. 

When you want to manage machines with different security-levels, like DCs and member servers, you should have separate user accounts for each security level. A  minimal separation would be something like in the below picture.

![](/assets/winrm-ansible-users.png)

So, technically this is the same solution that Microsoft recommends for Active Directory administration in general.  Check these documents for more information:

- [https://docs.microsoft.com/en-us/microsoft-identity-manager/pam/tier-model-for-partitioning-administrative-privileges](https://docs.microsoft.com/en-us/microsoft-identity-manager/pam/tier-model-for-partitioning-administrative-privileges)
- [https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/protecting-domain-administrative-credentials/ba-p/259210](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/protecting-domain-administrative-credentials/ba-p/259210)

