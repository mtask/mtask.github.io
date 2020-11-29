---
title: 'Monitoring login events with Powershell and WMI'
layout: 'qpost'
tags: ["windows","powershell","wmi"]
---

This post shows a small Powershell script that I created to capture login events using WMI event subscription in Windows.
Note that this method only applies to current Powershell session and is not persistent.  
  
What the script does in practice:

1. Specify query that returns [win32_LogOnSession](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logonsession) events
2. Use `Register-WmiEvent` to subscribe to these events
3. When `LogOnSession` event occurs:
   1. Find related username based on the `LogonId` information that is returned in the event
   2. Find SID of the username (tested only with non-ad machine/users)

Below is the script. It most likely is unnecessarily complex, but at least is seems to work as it should.

```powershell
# Get win32_LogOnSession events
$query = "Select TargetInstance From __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'win32_LogOnSession'"
# Subscripe to events based on the defined query
Register-WmiEvent -SourceIdentifier LogonCapture -Query $query -Action {
            # Get logon type from the WMI event
            $thisLogonType = $event.SourceEventArgs.NewEvent.TargetInstance.LogonType
            # Get logonID from the WMI event
            $thisLogonId = $event.SourceEventArgs.NewEvent.TargetInstance.LogonId
            # Get logged on users
            $LoggedOnUsers = Get-WmiObject -Class win32_loggedonuser | Select-Object Antecedent,Dependent
            # Loop over logged on users
            foreach ($userobj in $LoggedOnUsers) {
                # Parse logonID from the current item
                $LogonID = $userobj.Dependent | Select-String -Pattern 'win32_LogonSession\.LogonId="(.*)"' | % { $_.matches.groups[1] }
                # Check if the logonID matches with the ID of the WMI event
                if ($LogonID.Value -eq $thisLogonId ) {
                    # If logon IDs matched then extract associated username 
                    $username = $userobj.Antecedent | Select-String -Pattern ',Name="(.*)"' | % { $_.matches.groups[1] }
                    # Get SID of the username
                    $userObjForSid = New-Object System.Security.Principal.NTAccount($username.Value)
                    $strSID = $userObjForSid.Translate([System.Security.Principal.SecurityIdentifier])
                    # Write event details to console
                    Write-Host "New LogOn event for user $username (SID: $strSID) of type $thisLogonType"
                }
            }
               
}
```


Below is an example where I have saved the script as "monitor_login.ps1" and launched it. The shown output is coming from the `Register-WmiEvent` command. 

![](/assets/wmi_register.png)

After the event subscription was registered I logged in few times via RDP. The `New LogOn event for user...` texts are result from those logins.

![](/assets/wmi_capture_events.png)

You can find the below line from the script which constructs the output line.

```powershell
Write-Host "New LogOn event for user $username (SID: $strSID) of type $thisLogonType"
```
