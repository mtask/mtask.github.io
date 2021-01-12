---

title: 'Manage domain-joined Windows machines with Ansible'
layout: 'post'
tags: ["Windows", "Security"]

---

{:toc}

This post shows how to configure a domain-joined Windows machine to be managed with Ansible.

Ansible uses Windows Remote Management (WinRM) service to communicate with Windows machines. I Will use a domain with one member machine to deploy the WinRM service with a GPO and then configure the Ansible controller to use Kerberos authentication.



![image-20210112150034053](assets/image-20210112150034053.png)

I have also included some testing steps before the final Kerberos and WinRM over HTTPS configuration, so it's easier to spot what's wrong in case of an issue.

## Deploy WinRM service with GPO

1. Create a new GPO or edit existing one depending on your GPO strategy.

2. Open the GPO and go to `Computer Configuration > Policies > Administrative Templates > Windows Components > Windows Remote Management (WinRM) > WinRM Service`

3. Open the setting `Allow remote server management through WinRM`

4. Set setting to enabled and set IPv(4|6) filtering TBD

   ![image-20210112101632279](assets/image-20210112101632279.png)

   * I will also set `Allow basic authentication` and `Allow unencrypted traffic` to `enabled` for the first tests . Note that these are not needed if you only want to user Kerberos authentication with Ansible and/or do not want to test the configuration without HTTPS.

5. Go to `Go to Computer Configuration > Preferences > Control Panel Settings`

6. Right click the `service` and select `New > Service `

7. Select `...` next to the `Service name` and select the `WinRM ` service

   ![image-20210112120516929](assets/image-20210112120516929.png)

8. Set the `Startup` to `Automatic (Delayed Start)`  and `Service action` to `Start service` and click `OK`

   ![image-20210112120722920](assets/image-20210112120722920.png)

9. Save the GPO, go to a machine that gets settings from it, and run `gpudate /force` command.

10. Run the `Test-WSMan` cmdlet in Powershell to verify that WinRM  service is running.



## Testing the WinRM  connection with Powershell

From a machine in your domain run `Enter-PSSession <machine with WIRM running>`. I f you need to specify credentials for the connection then you can use something like this:

```powershell
$creds = Get-Credential
Enter-pssession <your machine> –credential $creds
```



![image-20210112122739023](assets/image-20210112122739023.png)

![image-20210112122847949](assets/image-20210112122847949.png)

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

4. Try the connection with ` ansible -i inventory/hosts -m win_ping win101`. You should get response like this:

   ```json
   win101 | SUCCESS => {
       "changed": false,
       "ping": "pong"
   }
   ```

If you get some errors like `"basic: the specified credentials were rejected by the server` then check your WinRM  configuration on the windows host using `winrm get winrm/config` command and verify that all settings are applied in the way they were specified with the GPO. Note that each setting specified with a GPO should have statement `[Source="GPO"]`.

## Certificate enrollment

I won't go through the Certificate Authority role installation, but go on from a point where Windows CA exists in the environment.

1. Create a new GPO or edit existing one depending on your GPO strategy.

2. Navigate to `Computer Configuration > Policies > Windows Settings > Security Settings > Public Key Policies`

3. Open `Certificate Services Client – Auto-Enrollment` and set the setting to `Enabled` and check the first two settings

   ![image-20210112143306258](assets/image-20210112143306258.png)

4. Click `OK` and right click `Automatic Certificate Request Settings > New > Automatic Certificate Request ...`

   * Certificate template:  `Computer` (or if you have another template then use that here)

   * Open `Automatic Certificate Request Settings` and ensure that you can see your template there.

     ![image-20210112143704676](assets/image-20210112143704676.png)

5. Ensure that the GPO is linked to a correct OU and go to your member machine and run `gpudate /force`

6. Go to your Certificate Authority and ensure that you can see the issued certificate

   ![image-20210112144348158](assets/image-20210112144348158.png)

7. In your member machine create WinRM  HTTPS listener using the command `winrm quickconfig -transport:https` and verify listeners using `winrm enumerate winrm/config/listener`

## Ansible test with HTTPS

1. Export your CAs root certificate. In the CA server you can run the command `certutil -ca.cert win_ca.crt` to export the certificate.
2. In ansible controller, create a directory `files` on the same directory level with the inventory and copy the certificate to there.
3. Add `ansible_winrm_ca_trust_path=files/win_ca.crt`
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

Now you can try the ` ansible -i inventory/hosts -m win_ping win101` command again. You can also try to run some arbitrary command like `ansible -i inventory/hosts -m win_shell -a "whoami" win101`.

I'm not including any playbook examples as there is nothing Windows specific expect Ansible's Windows modules. You can found list of Windows modules here: [https://docs.ansible.com/ansible/2.9/modules/list_of_windows_modules.html](https://docs.ansible.com/ansible/2.9/modules/list_of_windows_modules.html)


## Kerberos authentication with ansible

I will create a domain user "ansible" and add that user to member machine's local administrators group using GPO. Then I will configure Kerberos authentication for that user.

2. Create a new domain user "ansible"

   ![image-20210112154933885](assets/image-20210112154933885.png)

2. Create a new GPO or edit existing one depending on your GPO strategy

3. Open `Computer Configuration > Preferences > Control Panel Settings > Local Users and Groups`

5. Right click , select `New > Local Group` and `Update` the `Administrators (built-in)` group to include the `ansible` user.

   ![image-20210112155708589](assets/image-20210112155708589.png)

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
