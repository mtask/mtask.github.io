---
title: 'Monitoring Windows login events with WMI'
layout: 'post'
tags: ["Windows","Security"]
---

{:toc}

This post shows a small Powershell script that I created to capture login events using WMI event subscription in Windows.
Note that this method only applies to current Powershell session and is not persistent. 
I also show more persistent method using Managed Object Format and WMI repository.

## Using Powershell and Register-WmiEvent cmdlet

Here's a small script that I created to capture login events using WMI event subscription and Powershell.
What the script does in practice:

### Script content

1. Specify query that returns [win32_LogOnSession](https://docs.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logonsession) events
2. Use `Register-WmiEvent` to subscribe to these events
3. When `LogOnSession` event occurs:
   1. Find related username based on the `LogonId` information that is returned in the event
   2. Find SID of the username (tested only with non-ad machine/users)

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

### Example run

Below is an example where I have saved the script as "monitor_login.ps1" and launched it. The shown output is coming from the `Register-WmiEvent` command. 

![](/assets/wmi_register.png)

After the event subscription was registered I logged in few times via RDP. The `New LogOn event for user...` texts are result from those logins.

![](/assets/wmi_capture_events.png)

You can find the below line from the script which constructs the output line.

```powershell
Write-Host "New LogOn event for user $username (SID: $strSID) of type $thisLogonType"
```

## Using Managed Object Format and WMI repository

Here is an example of how to add persistent WMI event subscription by using [Managed Object Format (MOF)](https://docs.microsoft.com/en-us/windows/win32/wmisdk/managed-object-format--mof-) and [Mofcomp](https://docs.microsoft.com/en-us/windows/win32/wmisdk/mofcomp) compiler.

### Add subscriptions to WMI repository with MOF

Below is the MOF file I'm using. The basic idea is pretty simple. It defines a filter that captures `win32_LogOnSession` events and a consumer that writes output of `Get-WmiObject -Class win32_loggedonuser` to file `C:\users_<MM-dd-yyyy-HH-mm>.json`.

```powershell
// Set the namespace as root\subscription.
// The CommandLineEventConsumer is already compiled
// in the root\subscription namespace. 
#pragma namespace ("\\\\.\\Root\\subscription")

// Create an instance of the command line consumer
// and give it the alias $CMDLINECONSUMER

instance of CommandLineEventConsumer as $CMDLINECONSUMER
{
 Name = "CmdLineConsumer_Example";
 CommandLineTemplate = "powershell -Command \"Get-WmiObject -Class win32_loggedonuser | ConvertTo-Json | Out-File C:\\users_$(Get-Date -Format 'MM-dd-yyyy-HH-mm').json\"";
 RunInteractively = False;
};    

// Create an instance of the event filter
// and give it the alias $CMDLINEFILTER
// The filter queries for instance creation event
// for instances of the MyCmdLineConsumer class

instance of __EventFilter as $CMDLINEFILTER
{
    Name = "CmdLineFilter";
    EventNameSpace = "root\\cimv2";
    Query = "Select TargetInstance From __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'win32_LogOnSession'";
    QueryLanguage = "WQL";
};

// Create an instance of the binding
// between filter and consumer instances.

instance of __FilterToConsumerBinding
{
     Consumer = $CMDLINECONSUMER;
     Filter = $CMDLINEFILTER;
};
```

Next, I save the file as `test.mof` and compile it, so it's added to the WMI repository.

![](/assets/wmi_mofcomp.png)

### Explore WMI repository

One option to view the WMI repository is to use [WMI explorer](https://github.com/vinaypamnani/wmie2/release). Here's how the created filter and consumer can be observed in the app:

![](/assets/wmi_explorer_filter.png)

![](/assets/wmi_explorer_consumer.png)
