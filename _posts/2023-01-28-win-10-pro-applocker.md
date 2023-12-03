---
title: 'Some random Windows things (Applocker, Volatility, etc.)'
layout: 'post'
tags: ["Security", "Windows"]
---

This post contains some random Windows related things that I have found recently or have been tinkering with recently.

## Windows 10 Pro, Group Policy, and Applocker

I have been aware of the fact that you can't manage Applocker in Windows 10 Professional versions with Group Policy.
However, recently I found [this post](https://4sysops.com/archives/enable-applocker-on-windows-10-pro-and-windows-11-pro-with-powershell/) which stated:

> UPDATE: since build 22H2, Applocker works on Win10/11 Pro without needing my script. As it seems, Microsoft has changed its mind after all.

It's quite weird that Microsoft states:

> You can use the AppLocker CSP to configure AppLocker policies on any edition of Windows 10 and Windows 11 supported by Mobile Device Management (MDM). 
> You can only manage AppLocker with Group Policy on devices running Windows 10 and Windows 11 Enterprise, Windows 10 and Windows 11 Education, and Windows Server 2016.
>
> --https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/requirements-to-use-applocker 

I tested this myself with Windows 10 22H2 (OS build 19045.2486), and what do you know, it worked! I used a standalone Windows 10 installation and configured Applocker directly via Local Group Policy.
Initially I found this message in the machine's Applocker event logs..

> appidsvc.dll: applocker component not available on this sku

...but after installing all the available updates and reboot, it just worked, and Applocker was correcly logging to event logs.
Now I'm just wondering if this is something that can be trusted to work in future, because Microsoft's documentation contradicts with this, or haven't I just found some up-to-date documentation that actually mentions this.


If you want to get started with Applocker then here are some good resources:

* Blog post series from [Sami Laiho](https://samilaiho.com/):
  * https://4sysops.com/archives/applocker-whitelisting-vs-blacklisting/
  * https://4sysops.com/archives/creating-applocker-rules-from-the-windows-event-log/
  * https://4sysops.com/archives/applocker-audit-vs-enforced-mode/
  * https://4sysops.com/archives/hardening-applocker/
  * https://4sysops.com/archives/applocker-best-practices/

* [AaronLocker github project](https://github.com/microsoft/AaronLocker)

> AaronLocker is designed to make the creation and maintenance of robust, strict, application control for AppLocker and Windows Defender Application Control (WDAC) as easy and practical as possible.
> 
> --https://github.com/microsoft/AaronLocker

## Convert SIDs in secedit's USER_RIGHTS export with Powershell

When you use secedit to export User Rights Assignment the output looks something like this:

```ini
[Privilege Rights]
SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551
SeChangeNotifyPrivilege = *S-1-1-0,*S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeSystemtimePrivilege = *S-1-5-19,*S-1-5-32-544
SeCreatePagefilePrivilege = *S-1-5-32-544
SeDebugPrivilege = *S-1-5-32-544
SeRemoteShutdownPrivilege = *S-1-5-32-544
SeAuditPrivilege = *S-1-5-19,*S-1-5-20
SeIncreaseQuotaPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544
SeIncreaseBasePriorityPrivilege = *S-1-5-32-544,*S-1-5-90-0
SeLoadDriverPrivilege = *S-1-5-32-544
SeBatchLogonRight = *S-1-5-32-544,*S-1-5-32-551,*S-1-5-32-559
SeServiceLogonRight = *S-1-5-80-0
SeInteractiveLogonRight = Guest,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeSecurityPrivilege = *S-1-5-32-544
SeSystemEnvironmentPrivilege = *S-1-5-32-544
SeProfileSingleProcessPrivilege = *S-1-5-32-544
SeSystemProfilePrivilege = *S-1-5-32-544,*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420
SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20
SeRestorePrivilege = *S-1-5-32-544,*S-1-5-32-551
SeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeTakeOwnershipPrivilege = *S-1-5-32-544
SeDenyNetworkLogonRight = Guest
SeDenyInteractiveLogonRight = Guest
SeUndockPrivilege = *S-1-5-32-544,*S-1-5-32-545
SeManageVolumePrivilege = *S-1-5-32-544
SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555
SeImpersonatePrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6
SeCreateGlobalPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6
SeIncreaseWorkingSetPrivilege = *S-1-5-32-545
SeTimeZonePrivilege = *S-1-5-19,*S-1-5-32-544,*S-1-5-32-545
SeCreateSymbolicLinkPrivilege = *S-1-5-32-544
SeDelegateSessionUserImpersonatePrivilege = *S-1-5-32-544
```

I wanted to convert all those SID's automatically and have JSON formatted output, so I created a Powershell script for this.
My Powershell knowledge is quite mediocre so the script's code is what it is, but seemed to do what I wanted it to do.

```powershell
﻿$RESULT = @{}
$OUTFILE = $env:TEMP+"\out.cf"
# Use SecEdit to export USER_RIGHTS configuration
SecEdit.exe /export /areas USER_RIGHTS /cfg $OUTFILE >NULL
# Loop over output file's content
foreach($line in  Get-Content -Path $OUTFILE) {
    $line_arr = $line.Split(' ')
    # Seperate privilige name
    $PRIV = $line_arr[0]
    # Output contains some other lines as well..
    #.. and this ensures that we are only checking relevant lines
    if ($line -match '[A-Za-z]+\s=\s.*') {
        # Seperate SIDs that are seperated with comma
        foreach( $sid_str in $line_arr[2].Split(',') ) {
            # Some names are already converted lik "Guest"
            if ( $sid_str.StartsWith('*S-') ) {
                $sid_str = $sid_str.Replace('*', '')
                $CONVERTED_SID = $([wmi]"Win32_SID.SID='$sid_str'"|select -ExpandProperty AccountName)
                if ($RESULT.ContainsKey($PRIV) ) {
                    $RESULT[$PRIV] += $CONVERTED_SID
                }
                else{
                    $RESULT.add($PRIV, @($CONVERTED_SID))
                }
            }else {
                if ($RESULT.ContainsKey($PRIV) ) {
                    $RESULT[$PRIV] += $sid_str
                }
                else{
                    $RESULT.add($PRIV, @($sid_str))
                }

            }
        }
    }
}

# Remove SecEdit export file
del $OUTFILE
# Convert results to JSON
Write-Host $($RESULT | ConvertTo-Json -Depth 4)
```

The output looks like this:

```json
{
    "SeLoadDriverPrivilege":  [
                                  "Administrators"
                              ],
    "SeImpersonatePrivilege":  [
                                   "LOCAL SERVICE",
                                   "NETWORK SERVICE",
                                   "Administrators",
                                   "SERVICE"
                               ],
    "SeSystemtimePrivilege":  [
                                  "LOCAL SERVICE",
                                  "Administrators"
                              ],
    "SeDelegateSessionUserImpersonatePrivilege":  [
                                                      "Administrators"
                                                  ],
    "SeTakeOwnershipPrivilege":  [
                                     "Administrators"
                                 ],
    "SeDenyInteractiveLogonRight":  [
                                        "Guest"
                                    ],
    "SeBackupPrivilege":  [
                              "Administrators",
                              "Backup Operators"
                          ],
    "SeRemoteInteractiveLogonRight":  [
                                          "Administrators",
                                          "Remote Desktop Users"
                                      ],
    "SeIncreaseQuotaPrivilege":  [
                                     "LOCAL SERVICE",
                                     "NETWORK SERVICE",
                                     "Administrators"
                                 ],
    "SeSecurityPrivilege":  [
                                "Administrators"
                            ],
    "SeDebugPrivilege":  [
                             "Administrators"
                         ],
    "SeServiceLogonRight":  [
                                "ALL SERVICES"
                            ],
    "SeIncreaseWorkingSetPrivilege":  [
                                          "Users"
                                      ],
    "SeIncreaseBasePriorityPrivilege":  [
                                            "Administrators",
                                            "Window Manager Group"
                                        ],
    "SeShutdownPrivilege":  [
                                "Administrators",
                                "Users",
                                "Backup Operators"
                            ],
    "SeUndockPrivilege":  [
                              "Administrators",
                              "Users"
                          ],
    "SeBatchLogonRight":  [
                              "Administrators",
                              "Backup Operators",
                              "Performance Log Users"
                          ],
    "SeTimeZonePrivilege":  [
                                "LOCAL SERVICE",
                                "Administrators",
                                "Users"
                            ],
    "SeAssignPrimaryTokenPrivilege":  [
                                          "LOCAL SERVICE",
                                          "NETWORK SERVICE"
                                      ],
    "SeInteractiveLogonRight":  [
                                    "Guest",
                                    "Administrators",
                                    "Users",
                                    "Backup Operators"
                                ],
    "SeCreatePagefilePrivilege":  [
                                      "Administrators"
                                  ],
    "SeRestorePrivilege":  [
                               "Administrators",
                               "Backup Operators"
                           ],
    "SeSystemProfilePrivilege":  [
                                     "Administrators",
                                     "WdiServiceHost"
                                 ],
    "SeCreateGlobalPrivilege":  [
                                    "LOCAL SERVICE",
                                    "NETWORK SERVICE",
                                    "Administrators",
                                    "SERVICE"
                                ],
    "SeDenyNetworkLogonRight":  [
                                    "Guest"
                                ],
    "SeRemoteShutdownPrivilege":  [
                                      "Administrators"
                                  ],
    "SeNetworkLogonRight":  [
                                "Everyone",
                                "Administrators",
                                "Users",
                                "Backup Operators"
                            ],
    "SeManageVolumePrivilege":  [
                                    "Administrators"
                                ],
    "SeAuditPrivilege":  [
                             "LOCAL SERVICE",
                             "NETWORK SERVICE"
                         ],
    "SeProfileSingleProcessPrivilege":  [
                                            "Administrators"
                                        ],
    "SeCreateSymbolicLinkPrivilege":  [
                                          "Administrators"
                                      ],
    "SeSystemEnvironmentPrivilege":  [
                                         "Administrators"
                                     ],
    "SeChangeNotifyPrivilege":  [
                                    "Everyone",
                                    "LOCAL SERVICE",
                                    "NETWORK SERVICE",
                                    "Administrators",
                                    "Users",
                                    "Backup Operators"
                                ]
}
```


## Windows 10 memory analysis examples with Volatility3


I wanted to test how well [Volatility's Python3 version](https://github.com/volatilityfoundation/volatility3) works with recent Windows versions, 
so below is some examples with a memory dump from Windows 10 pro 22h2 version.

* List available Windows modules

```
$ python3 vol.py -f ~/dumps/memdump.mem --help|grep -i Windows -A 1
    windows.bigpools.BigPools
                        List big page pools.
    windows.callbacks.Callbacks
                        Lists kernel callbacks and notification routines.
    windows.cmdline.CmdLine
                        Lists virtual mapped sections.
...
```

Volatility may list some plugins that it failed to load at the end of the output. You can check why those plugins failed to load by running `python3 vol.py -f ~/dumps/memdump.mem -vv`. 
You may need to install some addittional Python libraries like `pefile`.


* List netstat information

```
python3 vol.py -f ~/dumps/memdump.mem windows.netstat
Volatility 3 Framework 2.4.1
Progress:  100.00		PDB scanning finished                        
Offset	Proto	LocalAddr	LocalPort	ForeignAddr	ForeignPort	State	PID	Owner	Created

0xbc8e3e50d010	TCPv4	10.10.0.3	50320	10.10.0.8	443	CLOSE_WAIT	356	SearchApp.exe	2023-01-29 13:44:19.000000 
...
```

* Get basic information of the image

```
python3 vol.py -f ~/dumps/memdump.mem windows.info
Volatility 3 Framework 2.4.1
Progress:  100.00		PDB scanning finished                                                                                              
Variable	Value

Kernel Base	0xf80248200000
DTB	0x153000
Symbols	file:///home/mtask/git/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/E2BA44E0E506968538EA272B1E5030C5-1.json.xz
Is64Bit	True
IsPAE	False
layer_name	0 WindowsIntel32e
memory_layer	1 FileLayer
KdVersionBlock	0xf80248e0f388
Major/Minor	15.19041
MachineType	34404
KeNumberProcessors	2
SystemTime	2023-01-29 16:25:53
NtSystemRoot	C:\Windows
NtProductType	NtProductWinNt
NtMajorVersion	10
NtMinorVersion	0
PE MajorOperatingSystemVersion	10
PE MinorOperatingSystemVersion	0
PE Machine	34404
PE TimeDateStamp	Fri Jul 11 07:43:16 1997
```

* Check for powershell process

```
python3 vol.py -f ~/dumps/memdump.mem windows.pslist | grep -i powershell
5852	4264	powershell.exe	0xbc8e3e054080	12	-	1	False	2023-01-29 14:10:20.000000 	N/A	Disabled
```

* Check parent process of the powershell process:

```
$ python3 vol.py -f ~/dumps/memdump.mem windows.pslist --pid 4264
Volatility 3 Framework 2.4.1
Progress:  100.00		PDB scanning finished                        
PID	PPID	ImageFileName	Offset(V)	Threads	Handles	SessionId	Wow64	CreateTime	ExitTime	File output

4264	5096	explorer.exe	0xbc8e3d6de340	89	-	1	False	2023-01-29 13:24:09.000000 	N/A	Disabled
```

* Find file handles of the Powershell process

Note that I had to install `python3-capstone` separately for this module to work 

```
$ python3 vol.py -f ~/dumps/memdump.mem windows.handles --pid  5852 | grep File
5852resspowershell.exe	0xbc8e37c148f0an0x40 finFile	0x100020	\Device\HarddiskVolume2\Windows\System32
5852	powershell.exe	0xbc8e37c13180	0x44	File	0x12019f	\Device\ConDrv\Connect
5852	powershell.exe	0xbc8e37c12500	0x48	File	0x12019f	\Device\ConDrv\Reference
5852	powershell.exe	0xbc8e3f291980	0xc4	File	0x100001	\Device\HarddiskVolume2\Windows\System32\WindowsPowerShell\v1.0\en-US\powershell.exe.mui
5852	powershell.exe	0xbc8e3f2050c0	0x164	File	0x100001	\Device\CNG
5852	powershell.exe	0xbc8e3f2becf0	0x1c0	File	0x120089	\Device\DeviceApi\CMApi
5852	powershell.exe	0xbc8e3f2b93e0	0x25c	File	0x100001	\Device\HarddiskVolume2\Windows\System32\en-GB\propsys.dll.mui
```

* Check processes with CmdLine options

```
python3 vol.py -f ~/dumps/memdump.mem windows.cmdline.CmdLine
Volatility 3 Framework 2.4.1
Progress:  100.00		PDB scanning finished                        
PID	Process	Args

4	System	Required memory at 0x20 is not valid (process exited?)
92	Registry	Required memory at 0x20 is not valid (process exited?)
348	smss.exe	\SystemRoot\System32\smss.exe
440	csrss.exe	%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
520	wininit.exe	wininit.exe
528	csrss.exe	%SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
616	winlogon.exe	winlogon.exe
660	services.exe	C:\Windows\system32\services.exe
680	lsass.exe	C:\Windows\system32\lsass.exe
772	fontdrvhost.ex	"fontdrvhost.exe"
...
```

* Get certificate list

```
python3 vol.py -f ~/dumps/memdump.mem windows.registry.certificates.Certificates
Volatility 3 Framework 2.4.1
Progress:  100.00		PDB scanning finished                        
Certificate path	Certificate section	Certificate ID	Certificate name

Software\Microsoft\SystemCertificates	Root	ProtectedRoots	-
Microsoft\SystemCertificates	AuthRoot	AutoUpdate	-
Microsoft\SystemCertificates	AuthRoot	AutoUpdate	-
Microsoft\SystemCertificates	AuthRoot	AutoUpdate	-
Microsoft\SystemCertificates	AuthRoot	AutoUpdate	-
Microsoft\SystemCertificates	AuthRoot	AutoUpdate	-
...
```

## Delete trusted root certificates with Powershell where subject does not match with `CN=Microsoft.*`.

For this to work properly you must set the following policy configuration: `Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off Automatic Root Certificates Update" -> "Enabled"` 
  
To make sure that the setting is correctly applied you can use this Powershell command: `Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot -Name DisableRootAutoUpdate`. The output should show value "1" for the "DisableRootAutoUpdate".
  
Try `gpupdate /force` if you get "not found" errors. If the key still didin't appear then try to reboot.
  
After the `DisableRootAutoUpdate` is correctly set, the below Powershell script can be used to remove root certificates where the subject doesn't match `CN=Microsoft.*`.

```powershell
﻿Get-ChildItem Cert:\LocalMachine\Root\* |
Where-Object { $_.Subject -notmatch 'CN=Microsoft.*'} |
Remove-Item
```

