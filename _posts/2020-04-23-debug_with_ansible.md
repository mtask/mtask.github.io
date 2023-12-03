---
title: 'Debugging Ansible modules'
layout: post
tags: ["Ansible"]
---
{:toc}

This is a small tutorial where I show how to dive inside Ansible's python modules in error debugging. This has been a useful trick when I have had an error with a module, and no matter how much verbosity I add, or use `DEBUG=1`, I still couldn't figure out what was the reason for the error. I'm sure there's more official way to debug modules, but so far, this way has covered my needs.



I'm not explaining regular Ansible usage, so following this requires some prior knowledge.



## Create a new playbook for testing

The directory structure for the playbook:

```
testplay/
├── hosts
└── test_play.yml
```

* `test_play.yml` file content:

```yaml
---
- hosts: testmachines
  tasks:
    - name: "Try to add user"
      user:
        name: "bob"
```

Spoiler alert, the play is missing `become: yes` (unless executed as root). I was lazy to create some complex error scenario, so I just use this to demonstrate the concept. 

* `hosts` file content:

```
[testmachines]
<YOUR_SERVER> ansible_user=<YOUR_USER>
```

## Test the playbook

Let's just run the playbook and see that we are getting the error as we expected. Like said, I just didn't figure out a better scenario, for now, so just imagine that the error is something where you have no idea what is causing it.

```bash
~$ ansible-playbook -i hosts test_play.yml

PLAY [testmachines] ***********************************************************************************************************************************************************************************************

TASK [Try to add user] ********************************************************************************************************************************************************************************************
[WARNING]: Platform linux on host 1.2.3.4 is using the discovered Python interpreter at /usr/bin/python, but future installation of another Python interpreter could change this. See
https://docs.ansible.com/ansible/2.9/reference_appendices/interpreter_discovery.html for more information.
fatal: [1.2.3.4]: FAILED! => {"ansible_facts": {"discovered_interpreter_python": "/usr/bin/python"}, "changed": false, "msg": "useradd: Permission denied.\nuseradd: cannot lock /etc/passwd; try again later.\n", "name": "bob", "rc": 1}

PLAY RECAP ********************************************************************************************************************************************************************************************************
1.2.3.4            : ok=0    changed=0    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0   
```

Use `--ask-pass` if you don't have SSH keys configured with the target machine.

## Keep remote files

When Ansible executes tasks it will move bunch of Python scripts to remote host and then executes those scripts. Usually it will remove these files after the execution. By specifying `ANSIBLE_KEEP_REMOTE_FILES` variable to `1`,  Ansible won't remove these files from the remote host.

Now execute the playbook this way and include some verbosity flags. 

```bash
~$ ANSIBLE_KEEP_REMOTE_FILES=1 ansible-playbook -vvvv -i hosts test_play.yml 
ansible-playbook 2.9.6
...[debug output]...
"'"'/usr/bin/python /home/user/.ansible/tmp/ansible-tmp-1587573128.18-1362966474151/AnsiballZ_user.py && sleep 0'"'"''
...
fatal: [1.2.3.4]: FAILED! => {
....
```

Search the output for lines like `"'"'/usr/bin/python /home/<ansible_user>/.ansible/tmp.[..snip..]..AnsiballZ_user.py && sleep 0'"'"''` and copy the python command from the last matching line.

Next, SSH into your remote host and execute the python command. 

```bash
~$ /usr/bin/python /home/user/.ansible/tmp/ansible-tmp-1587573128.18-1362966474151/AnsiballZ_user.py
{"msg": "useradd: Permission denied.\nuseradd: cannot lock /etc/passwd; try again later.\n", "failed": true, "rc": 1, "name": "bob", "invocation": {"module_args": {"comment": null, "ssh_key_bits": 0, "update_password": "always", "non_unique": false, "force": false, "ssh_key_type": "rsa", "create_home": true, "password_lock": null, "ssh_key_passphrase": null, "uid": null, "home": null, "append": false, "skeleton": null, "ssh_key_comment": "ansible-generated on mc1", "group": null, "system": false, "state": "present", "role": null, "hidden": null, "local": null, "authorization": null, "profile": null, "shell": null, "expires": null, "ssh_key_file": null, "groups": null, "move_home": false, "password": null, "name": "bob", "seuser": null, "remove": false, "login_class": null, "generate_ssh_key": null}}}
```

It's the same error message we had during the playbook execution, so we have the correct file.



## Extract modules from the remote files

I haven't look into ansible file structure too deeply, but enough to know that modules are not directly in this file. Instead, the file includes variable `ZIPDATA`, and its value contains a Base64 encoded zip file.

```bash
~$ grep ZIPDATA /home/user/.ansible/tmp/ansible-tmp-1587573128.18-1362966474151/AnsiballZ_user.py
ZIPDATA = """UEsDBBQAAAAIAAScllCdxfFrNwAAAEgAAAAgAAAAYW5zaW...
```

Let's extract the B64 encoded portion, decode it, and create a zip file from the output.

```
~$ grep -oP '"""(.*?)"""' /home/user/.ansible/tmp/ansible-tmp-1587573128.18-1362966474151/AnsiballZ_user.py | tr -d \" | base64 -d > zipfile.zip
~$ file zipfile.zip 
zipfile.zip: Zip archive data, at least v2.0 to extract

```

Now unzip the file:

```bash
~$ unzip zipfile.zip 
Archive:  zipfile.zip
  inflating: ansible/module_utils/__init__.py  
  inflating: ansible/__init__.py     
  inflating: ansible/module_utils/basic.py  
  inflating: ansible/module_utils/distro/__init__.py  
  inflating: ansible/module_utils/_text.py  
  inflating: ansible/module_utils/common/text/formatters.py  
  inflating: ansible/module_utils/common/valusertion.py  
  inflating: ansible/module_utils/common/text/converters.py  
  inflating: ansible/module_utils/pycompat24.py  
  inflating: ansible/module_utils/common/__init__.py  
  inflating: ansible/module_utils/common/text/__init__.py  
  inflating: ansible/module_utils/common/process.py  
  inflating: ansible/module_utils/parsing/convert_bool.py  
  inflating: ansible/module_utils/common/_utils.py  
  inflating: ansible/module_utils/common/_collections_compat.py  
  inflating: ansible/module_utils/parsing/__init__.py  
  inflating: ansible/module_utils/common/_json_compat.py  
  inflating: ansible/module_utils/six/__init__.py  
  inflating: ansible/module_utils/common/sys_info.py  
  inflating: ansible/module_utils/common/parameters.py  
  inflating: ansible/module_utils/common/file.py  
  inflating: ansible/module_utils/common/collections.py  
  inflating: ansible/module_utils/distro/_distro.py  
  inflating: ansible/modules/system/user.py  
  inflating: ansible/modules/__init__.py  
  inflating: ansible/modules/system/__init__.py  
```



## Search for the needed module

We know that our error happened during the task, which was using the user module. Check Ansible's [documentation](https://docs.ansible.com/ansible/latest/modules/user_module.html) for that module. Inside the documentation page, there is an *Edit on GitHub* link, and by following the link, you can see that `user.py` is the python file for the module. 

Search `user.py` from the unzipped folder:

```bash
~$ find ./ansible/ -name "user.py"
./ansible/modules/system/user.py
```



Open the file and add `print("Our debug test")` line to `create_user` method inside the module.

*  So, from: 
```python
def create_user(self):
    # by default we use the create_user_useradd method
    return self.create_user_useradd() 
```
*  To:  
```python
def create_user(self):
    # by default we use the create_user_useradd method
    print("Our debug test")
    return self.create_user_useradd()
```

Next:

1.  Zip the `ansible` folder:

```bash
~$ zip -r newzip.zip ansible
```

2.  B64 encode the content, and forward stdout to bottom of the `AnsiballZ_user.py` file.

```bash
$ cat newzip.zip | base64 -w 0 >> /home/user/.ansible/tmp/ansible-tmp-1587573128.18-1362966474151/AnsiballZ_user.py
```

3. Open the file
4. Cut the new encoded value from the file's last line. 
5. Replace `ZIPFILE` variable's old value with the new value
6. Close the file
7. Execute the script again

```bash
~$ /usr/bin/python /home/user/.ansible/tmp/ansible-tmp-1587573128.18-1362966474151/AnsiballZ_user.py
```

8. Check output (Hint: you should now see *Our debug test* in the output )

```bash
~$ /usr/bin/python /home/user/.ansible/tmp/ansible-tmp-1587573128.18-1362966474151/AnsiballZ_user.py
Our debug test

{"msg": "useradd: Permission denied.\nuseradd: cannot lock /etc/passwd; try again later.\n", "failed": true, "rc": 1, "name": "bob", "invocation": {"module_args": {"comment": null, "ssh_key_bits": 0, "update_password": "always", "non_unique": false, "force": false, "ssh_key_type": "rsa", "create_home": true, "password_lock": null, "ssh_key_passphrase": null, "uid": null, "home": null, "append": false, "skeleton": null, "ssh_key_comment": "ansible-generated on mc1", "group": null, "system": false, "state": "present", "role": null, "hidden": null, "local": null, "authorization": null, "profile": null, "shell": null, "expires": null, "ssh_key_file": null, "groups": null, "move_home": false, "password": null, "name": "bob", "seuser": null, "remove": false, "login_class": null, "generate_ssh_key": null}}}
```



## Recap

Printing *Our debug test* may not have been the most useful thing to do, but I hope you see the potential value with a more complex error situation. You can, for example, add multiple print statements to see where execution stops inside the module, or you can do some more advanced python debugging.
