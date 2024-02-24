---
title: 'Query and analyze Wazuh indexer data with Python'
layout: 'post'
tags: ["Security", "LogAnalysis"]
---
{:toc}

In this post I will show how to query data from [Wazuh indexer](https://github.com/wazuh/wazuh-indexer) using Python's requests module and some analysis examples with [Pandas](https://pandas.pydata.org/) library.

If you are not familiar with [Wazuh](https://wazuh.com/platform/overview/) it's an open source security platform. 
It has really great search and visualization capabilities and usually this kind of direct quering of the Indexer is not necessary,
but there could be situations where it might still be handy. 

Wazuh indexer is a open source fork from OpenSearch, so you can pretty much check OpenSearch's documentation for reference, and also Elasticsearch's to some extent.

## Quering and analyzing Windows logon events

Here's an example of how to query Windows logon events from the Wazuh archives.

Wazuh archives are not enabled by default and you can find instructions to enable it from [here](https://documentation.wazuh.com/current/user-manual/manager/wazuh-archives.html).

First, we will create a file `creds.json` that will have the credentials we use to authenticate with wazuh indexer. Content of the JSON file should look like this:

```json
{"username": "<username>", "password": "<password>"}
```

Then we can import some needed moduls and load the `creds.json`.


```python
import requests
import json
import pandas as pd
from requests.auth import HTTPBasicAuth
from datetime import datetime

with open('creds.json') as f:
    data = json.load(f)
    user = data['username']
    password = data['password']
```

Next, we define a query to search for Windows logon events (4624).

```python
# maximum number of results to return
result_max = 1000
query = {"from" : 0, "size" : result_max,
         "query":
          {
            "match":{"data.win.system.eventID": "4624"}
          }
        }
```

Next, we define the target index or indices for the query. Note that wildcards are supported like in the example. We also set base address for the Wazuh indexer.


```python
target_index = "wazuh-archives-4.x-2024.02.*"
# Wazuh indexer URI e.g. "https://my-server.local:9200"
wazuh_server = https://127.0.0.1:9200
```

The base structure for Wazuh's archive indices is `wazuh-alerts-<version>.x-<date>`, so in my above example, I'm targeting all the archive indices from february.

Next, we are ready to execute the actual query.


```python
r = requests.post(f"{wazuh_server}/{target_index}/_search", json=query, verify=False, auth=HTTPBasicAuth(user,password))
```

Note that I have `verify=False` set as I'm doing queries locally over localhost address. You should use verified TLS connections with remote connections.

### Verifying results

Let's verify that we got some results. Actual result data is found in JSON path `_source.hits.hits.data`. We can first check how many hits there was in total.


```python
print(r.json()['hits']['total']['value'])
```
```
    318
```


We can also verify that we have the data for each hit. This could differ if we wouldn't have defined `from`/`size` in our query, but with limit set in 1000 we should get all the data.


```python
print(len(r.json()['hits']['hits']))
```
```
    318
```

### Analyzing results

Now that we know there was some data found we can do some analysis.
Below code loops over the results and prints out time, username and computer of the event.

I have `break` set at the end just to see one example output, but removing the `break` would result printing all the results.


```python
for hit in r.json()['hits']['hits']:
    win_event_data = hit['_source']['data']['win']['eventdata']
    win_system_data = hit['_source']['data']['win']['system']
    print(win_system_data['systemTime'])
    print(win_event_data['targetUserName'])
    print(win_system_data['computer'])
    break
```
```
    2024-02-20T12:15:01.2249938Z
    SYSTEM
    EXAMPLE-MACHINE1
```


With Windows' logons [the logon type](https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types) is usually something you want to check so lets add that.


```python
for hit in r.json()['hits']['hits']:
    win_event_data = hit['_source']['data']['win']['eventdata']
    win_system_data = hit['_source']['data']['win']['system']
    print(win_system_data['systemTime'])
    print(win_event_data['targetUserName'])
    print(win_event_data['logonType'])
    print(win_system_data['computer'])
    break
```
```
   2024-02-20T12:15:01.2249938Z
   SYSTEM
   5
   EXAMPLE-MACHINE1
```



We can do a quick mapper dictionary to enrich the logon type from number to string that tells more about the actual logon type.


```python
logon_types = {
    "2":  "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkClearText",
    "9": "NewCredentials",
    "10": "RemoteInterActive",
    "11": "CachedInteractive"
}
```

Now, let's do another loop, but create a list of dicts with all the results. Each dict will have the following data of one event:

```json
{"date": "<date>", "computer": "<hostname>", "username": "<target user>", "logontype": "<logon type>", "logontype_descr": "<logon type description>"}
```


```python
logons = []
for hit in r.json()['hits']['hits']:
    
    win_event_data = hit['_source']['data']['win']['eventdata']
    win_system_data = hit['_source']['data']['win']['system']
    # Put logon type to own variable and then use that with the mapper
    win_logon_type = win_event_data['logonType']
    win_dt = datetime.strptime(win_system_data['systemTime'][:-4], '%Y-%m-%dT%H:%M:%S.%f')
    _logon = {
        "date": win_dt,
        "computer": win_system_data['computer'],
        "username": win_event_data['targetUserName'],
        "logontype": win_logon_type,
        "logontype_descr": logon_types[win_logon_type]
    }
    logons.append(_logon) 
```

Here's the first event from the list as an example. I changed `systemTime` from string to datetime object, so it's possible to filter data based on time.

```python
print(logons[0])
```
```python
    {'date': datetime.datetime(2024, 2, 20, 12, 15, 1, 224900), 'computer': 'EXAMPLE-MACHINE1', 'username': 'SYSTEM', 'logontype': '5', 'logontype_descr': 'Service'}
```

Now we have the main information from the Logon events neatly structured. We can put the data into a Panda's data frame for further analysis.


```python
df = pd.DataFrame(logons)
```

Let's check all the events where the logon type is not 5 (*Service*).


```python
df[(df['logontype'] != '5')]
```




<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>date</th>
      <th>computer</th>
      <th>username</th>
      <th>logontype</th>
      <th>logontype_descr</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>45</th>
      <td>2024-02-08 16:26:23.383800</td>
      <td>EXAMPLE-MACHINE2</td>
      <td>exampleuser1</td>
      <td>7</td>
      <td>Unlock</td>
    </tr>
    <tr>
      <th>62</th>
      <td>2024-02-08 18:29:36.678200</td>
      <td>EXAMPLE-MACHINE2</td>
      <td>DWM-2</td>
      <td>2</td>
      <td>Interactive</td>
    </tr>
    <tr>
      <th>76</th>
      <td>2024-02-08 16:26:23.282300</td>
      <td>EXAMPLE-MACHINE2</td>
      <td>exampleuser1</td>
      <td>11</td>
      <td>CachedInteractive</td>
    </tr>
    <tr>
      <th>94</th>
      <td>2024-02-08 18:29:36.600500</td>
      <td>EXAMPLE-MACHINE2</td>
      <td>UMFD-2</td>
      <td>2</td>
      <td>Interactive</td>
    </tr>
    <tr>
      <th>95</th>
      <td>2024-02-08 18:29:36.678200</td>
      <td>EXAMPLE-MACHINE2</td>
      <td>DWM-2</td>
      <td>2</td>
      <td>Interactive</td>
    </tr>
    <tr>
      <th>171</th>
      <td>2024-02-24 15:00:11.339700</td>
      <td>EXAMPLE-MACHINE1</td>
      <td>exampleuser2</td>
      <td>11</td>
      <td>CachedInteractive</td>
    </tr>
    <tr>
      <th>228</th>
      <td>2024-02-24 15:00:11.399500</td>
      <td>EXAMPLE-MACHINE1</td>
      <td>exampleuser2</td>
      <td>7</td>
      <td>Unlock</td>
    </tr>
    <tr>
      <th>290</th>
      <td>2024-02-19 21:10:09.815100</td>
      <td>EXAMPLE-MACHINE2</td>
      <td>UMFD-2</td>
      <td>2</td>
      <td>Interactive</td>
    </tr>
    <tr>
      <th>291</th>
      <td>2024-02-19 09:20:40.668400</td>
      <td>EXAMPLE-MACHINE1</td>
      <td>exampleuser2</td>
      <td>11</td>
      <td>CachedInteractive</td>
    </tr>
    <tr>
      <th>292</th>
      <td>2024-02-19 09:20:40.720900</td>
      <td>EXAMPLE-MACHINE1</td>
      <td>exampleuser2</td>
      <td>7</td>
      <td>Unlock</td>
    </tr>
    <tr>
      <th>312</th>
      <td>2024-02-19 21:10:09.887700</td>
      <td>EXAMPLE-MACHINE2</td>
      <td>DWM-2</td>
      <td>2</td>
      <td>Interactive</td>
    </tr>
    <tr>
      <th>313</th>
      <td>2024-02-19 21:10:09.887700</td>
      <td>EXAMPLE-MACHINE2</td>
      <td>DWM-2</td>
      <td>2</td>
      <td>Interactive</td>
    </tr>
  </tbody>
</table>
</div>



We can check the total count for different logon types.


```python
pd.DataFrame(df['logontype_descr'].value_counts())
```




<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th>count</th>
      <th>logontype_descr</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>Service</th>
      <td>306</td>
    </tr>
    <tr>
      <th>Interactive</th>
      <td>6</td>
    </tr>
    <tr>
      <th>Unlock</th>
      <td>3</td>
    </tr>
    <tr>
      <th>CachedInteractive</th>
      <td>3</td>
    </tr>
  </tbody>
</table>
</div>



It could be interesting to search for logon events in between specific hours. To do this, I'll will first change the index of the data frame to the `date` column.


```python
df = df.set_index('date')
```

Now we can use `between_time` function to search between specific hours.


```python
df.between_time("17:00", "8:00")
```




<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th>date</th>
      <th>computer</th>
      <th>username</th>
      <th>logontype</th>
      <th>logontype_descr</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>2024-02-08 17:01:07.405700</th>
      <td>EXAMPLE-MACHINE2</td>
      <td>SYSTEM</td>
      <td>5</td>
      <td>Service</td>
    </tr>
    <tr>
      <th>2024-02-08 18:02:14.302700</th>
      <td>EXAMPLE-MACHINE2</td>
      <td>SYSTEM</td>
      <td>5</td>
      <td>Service</td>
    </tr>
    <tr>
      <th>2024-02-08 18:02:24.544600</th>
      <td>EXAMPLE-MACHINE2</td>
      <td>SYSTEM</td>
      <td>5</td>
      <td>Service</td>
    </tr>
    <tr>
      <th>2024-02-08 18:03:46.177100</th>
      <td>EXAMPLE-MACHINE2</td>
      <td>SYSTEM</td>
      <td>5</td>
      <td>Service</td>
    </tr>
    <tr>
      <th>2024-02-08 18:04:26.899100</th>
      <td>EXAMPLE-MACHINE2</td>
      <td>SYSTEM</td>
      <td>5</td>
      <td>Service</td>
    </tr>
    <tr>
      <th>...</th>
      <td>...</td>
      <td>...</td>
      <td>...</td>
      <td>...</td>
    </tr>
    <tr>
      <th>2024-02-19 21:10:09.887700</th>
      <td>EXAMPLE-MACHINE2</td>
      <td>DWM-2</td>
      <td>2</td>
      <td>Interactive</td>
    </tr>
    <tr>
      <th>2024-02-19 21:09:22.045200</th>
      <td>EXAMPLE-MACHINE2</td>
      <td>SYSTEM</td>
      <td>5</td>
      <td>Service</td>
    </tr>
    <tr>
      <th>2024-02-19 21:10:00.808600</th>
      <td>EXAMPLE-MACHINE2</td>
      <td>SYSTEM</td>
      <td>5</td>
      <td>Service</td>
    </tr>
    <tr>
      <th>2024-02-19 21:10:14.969700</th>
      <td>EXAMPLE-MACHINE2</td>
      <td>SYSTEM</td>
      <td>5</td>
      <td>Service</td>
    </tr>
    <tr>
      <th>2024-02-19 21:10:14.837200</th>
      <td>EXAMPLE-MACHINE2</td>
      <td>SYSTEM</td>
      <td>5</td>
      <td>Service</td>
    </tr>
  </tbody>
</table>
</div>


## Quering and analyzing vulnerability status

This example shows how to query vulnerability events from Wazuh alerts and then filter down the results to get situational picture of the vulnerability status in you environment.

I have to mention that Wazuh has really nice pre-built dashboards for vulnerability status, so mostly get this type of information out of the box.
Only limitation is that it limits pre-built visualization per host (agent), so you don't really get "big picture" dashboards without building one yourself.

I think this kind of requests+Pandas approach can currently allow better vulnerability status analysis for the whole environment instead of one host.
There's also some deduplication needed for the events which might be hard to do directly within the Wazuh indexer.

In this example, we are doing a similar query as before. The main difference is that we are now targeting `wazuh-alerts*` indices and match events where field `data.vulnerability.status` is `Active` or `Solved`.

Below is the full code which is mostly same as the previous example. It also uses `creds.json` file for authentication.


```python
import requests
import json
import pandas as pd
from requests.auth import HTTPBasicAuth
from datetime import datetime
from dateutil.relativedelta import relativedelta 

target_index = "wazuh-alerts-4.x-2024.02*"
wazuh_server = "https://127.0.0.1:9200"

with open('creds.json') as f:
    data = json.load(f)
    user = data['username']
    password = data['password']

# maximum number of results to return
result_max = 1000
query = {"from" : 0, "size" : result_max,
         "query":
         {"bool":
          {"should":
           [
               {"match":{"data.vulnerability.status": "Active"}},
               {"match":{"data.vulnerability.status": "Solved"}}
           ]
          }
         }
        }


r = requests.post(f"{wazuh_server}/{target_index}/_search", json=query, verify=False, auth=HTTPBasicAuth(user,password))

vulns = []
for hit in r.json()['hits']['hits']:
    vuln_data = hit['_source']['data']['vulnerability']
    vuln = {
        "timestamp": datetime.strptime(hit['_source']['@timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ'),
        "affected": hit['_source']['agent']['name'],
        "CVE": vuln_data['cve'],
        "package": vuln_data['package']['name'],
        "status": vuln_data['status']
    }
    vulns.append(vuln)
df = pd.DataFrame(vulns)
df = df.set_index('timestamp')
```

Now we have the results in a data frame that is indexed by the timestamp and results look like this.

<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>affected</th>
      <th>CVE</th>
      <th>package</th>
      <th>status</th>
    </tr>
    <tr>
      <th>timestamp</th>
      <th></th>
      <th></th>
      <th></th>
      <th></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>2024-02-24 05:04:30.904</th>
      <td>testmachine1</td>
      <td>CVE-2024-25629</td>
      <td>libc-ares2</td>
      <td>Active</td>
    </tr>
    <tr>
      <th>2024-02-24 15:01:12.572</th>
      <td>testmachine2</td>
      <td>CVE-2024-21341</td>
      <td>Windows 10</td>
      <td>Active</td>
    </tr>
    <tr>
      <th>2024-02-24 15:01:12.595</th>
      <td>testmachine2</td>
      <td>CVE-2024-21338</td>
      <td>Windows 10</td>
      <td>Active</td>
    </tr>
    <tr>
      <th>2024-02-24 19:17:36.220</th>
      <td>testmachine1</td>
      <td>CVE-2023-42117</td>
      <td>exim4-base</td>
      <td>Active</td>
    </tr>
    <tr>
      <th>2024-02-24 19:17:37.211</th>
      <td>testmachine1</td>
      <td>CVE-2021-3981</td>
      <td>grub-common</td>
      <td>Active</td>
    </tr>
    <tr>
      <th>...</th>
      <td>...</td>
      <td>...</td>
      <td>...</td>
      <td>...</td>
    </tr>
    <tr>
      <th>2024-02-13 18:01:53.392</th>
      <td>testmachine1</td>
      <td>CVE-2023-5679</td>
      <td>bind9-dnsutils</td>
      <td>Active</td>
    </tr>
    <tr>
      <th>2024-02-13 18:01:53.475</th>
      <td>testmachine1</td>
      <td>CVE-2023-5679</td>
      <td>bind9-host</td>
      <td>Active</td>
    </tr>
    <tr>
      <th>2024-02-13 18:01:58.236</th>
      <td>testmachine1</td>
      <td>CVE-2023-4408</td>
      <td>bind9-dnsutils</td>
      <td>Active</td>
    </tr>
    <tr>
      <th>2024-02-13 18:01:58.405</th>
      <td>testmachine1</td>
      <td>CVE-2023-4408</td>
      <td>bind9-libs</td>
      <td>Active</td>
    </tr>
    <tr>
      <th>2024-02-13 18:01:58.630</th>
      <td>testmachine1</td>
      <td>CVE-2023-50387</td>
      <td>bind9-dnsutils</td>
      <td>Active</td>
    </tr>
  </tbody>
</table>
</div>

At this point we might have duplicate data that does not give very clear picture of the environments vulnerability status. Wazuh will report same vulnerability during the every scan if it's not fixed so "duplicate" events may accumalate.

We can get better situational picture if we order the events by timestamp and then remove duplicates based on fields "CVE" and "affected". After this we have last events where "CVE" and "affected" fields are unique so effectively we get the latest status per vulnerability by host.


```python
df = df.sort_values('timestamp').drop_duplicates(['CVE','affected'], keep='last')
```

Now we can futher filter the results to see events where the vulnerability status is still "Active".

```python
df[(df['status'] == 'Active')]
```


<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>affected</th>
      <th>CVE</th>
      <th>package</th>
      <th>status</th>
    </tr>
    <tr>
      <th>timestamp</th>
      <th></th>
      <th></th>
      <th></th>
      <th></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>2024-02-16 18:23:06.593</th>
      <td>testmachine1</td>
      <td>CVE-2024-22667</td>
      <td>xxd</td>
      <td>Active</td>
    </tr>
    <tr>
      <th>2024-02-24 05:04:30.904</th>
      <td>testmachine1</td>
      <td>CVE-2024-25629</td>
      <td>libc-ares2</td>
      <td>Active</td>
    </tr>
  </tbody>
</table>
</div>



You can also check statistics for solved events within a specific period. Here's an example to get results for the last month without hard coded dates.


```python
now = datetime.now()
now_date = now.strftime('%Y-%m-%d')
last_month_date = (now + relativedelta(months=-1)).strftime('%Y-%m-%d')
solved = df[(df['status'] == 'Solved')].loc[last_month_date:now_date]['CVE'].count()
print(f"{solved} vulnerabilities were resolved during the last month.")
```
```python
    234 vulnerabilities were resolved during the last month.
```

You can also check amount of "Active" vulnerabilities per host with hosts that have at least one "Active" vulnerability.


```python
pd.DataFrame(df[(df['status'] == 'Active')]['affected'].value_counts())
```

<div>
<style scoped>
    .dataframe tbody tr th:only-of-type {
        vertical-align: middle;
    }

    .dataframe tbody tr th {
        vertical-align: top;
    }

    .dataframe thead th {
        text-align: right;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>count</th>
    </tr>
    <tr>
      <th>affected</th>
      <th></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>testmachine1</th>
      <td>2</td>
    </tr>
  </tbody>
</table>
</div>

