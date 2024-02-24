---
title: 'Log analysis with Pandas'
layout: 'post'
tags: ["Security", "LogAnalysis"]
---
{:toc}

This post shows how to analyze raw log data with Python data analysis library [Pandas](https://pandas.pydata.org/). I'm using Apache's access logs as an example and will show how to:

* Parse log data to Pandas Data Frame (DF)
* Analyze data within the DF.

## Using Jupyter Notebook for instant results

[Jupyter Notebook](https://jupyter.org/) is an excellent tool to do this kind of analysis.

```bash
pip install notebook
jupyter notebook
```

It will automatically output Pandas DFs in table format and enables quick testing for different things.

## Installing Pandas

Pandas can be installed with pip. I also install pyarrow because running Pandas gives warning that it's soon required by the framework.

```bash
pip install pandas
pip install pyarrow
```

You can also install dependencies within the Jupyter Notebook. Just add `!` in front of the command in a code block.

```bash
!pip install pandas
!pip install pyarrow
# Add "> /dev/null" at the end if you want to omit the output from the installation.
```

## Importing dependencies and downloading log sample

First we need to import necessary dependencies.


```python
import pandas as pd
import re
import os
import urllib.request
```

Then we will download a log sample and save it as `log_samples/apache.sample.log`. 
I'm using log sample from Elastic's Github repo. 

Change `APACHE_LOG_FILE_URL` variable if you want to user sample from some other source.

```python
APACHE_LOG_FILE_URL = 'https://raw.githubusercontent.com/elastic/examples/master/Common%20Data%20Formats/apache_logs/apache_logs'
if not os.path.isdir("log_samples"):
    os.mkdir("log_samples")
apache_log_file = 'log_samples/apache.sample.log'
urllib.request.urlretrieve(APACHE_LOG_FILE_URL, apache_log_file)
```

## Normalizing logs to Pandas DataFrame

Here I will show how to parse sample Apache access log file to Pandas Data Frame.
The main task in the below parser code is to normalize data from a log event using regular expression statement defined in variable `APACHE_RE`. 

```python
APACHE_RE = r'^((?:\d+\.){3}\d+).*\[(.*)\]\s"(.*)"\s(\d{3})\s(\d+|-)\s"(.*)"\s"(.*)"?'
apache_lines = []
# Loop appends regular expression search results to variable "apache_lines"
with open(apache_log_file, 'r') as apache_log:
    for line in apache_log:
        r = re.search(APACHE_RE, line)
        if r:
            if len(r.groups()) == 7:
                apache_lines.append(list(r.groups()))
        else:
            print(line)
# This line converts "apache_lines" to DF and specifies column names
df = pd.DataFrame(apache_lines, columns = ['IP', 'DATE', 'URL', 'STATUS', 'BYTES', 'REFERRER', 'UserAgent'])
df
```

Now the log data is in variable `df` and outputting the content would look like in the table below.

Note how I did not use `print(df)` because I'm using the Jupyter Notebook myself. Inside a Notebook it will automatically output the table in graphical format.

With `print(df)` the output would be shown in text format as if running the code directly in a terminal.

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
        overflow: auto;
        width: 100%;
    }
    table {
        display: block;
        overflow-x: auto;
        white-space: nowrap;
    }
    table tbody {
        display: table;
        width: 100%;
    }
</style>
<table border="1" class="dataframe">
  <thead>
    <tr style="text-align: right;">
      <th></th>
      <th>IP</th>
      <th>DATE</th>
      <th>URL</th>
      <th>STATUS</th>
      <th>BYTES</th>
      <th>REFERRER</th>
      <th>UserAgent</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>83.149.9.216</td>
      <td>17/May/2015:10:05:03 +0000</td>
      <td>GET /presentations/logstash-monitorama-2013/im...</td>
      <td>200</td>
      <td>203023</td>
      <td>http://semicomplete.com/presentations/logstash...</td>
      <td>Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1)...</td>
    </tr>
    <tr>
      <th>1</th>
      <td>83.149.9.216</td>
      <td>17/May/2015:10:05:43 +0000</td>
      <td>GET /presentations/logstash-monitorama-2013/im...</td>
      <td>200</td>
      <td>171717</td>
      <td>http://semicomplete.com/presentations/logstash...</td>
      <td>Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1)...</td>
    </tr>
    <tr>
      <th>2</th>
      <td>83.149.9.216</td>
      <td>17/May/2015:10:05:47 +0000</td>
      <td>GET /presentations/logstash-monitorama-2013/pl...</td>
      <td>200</td>
      <td>26185</td>
      <td>http://semicomplete.com/presentations/logstash...</td>
      <td>Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1)...</td>
    </tr>
    <tr>
      <th>3</th>
      <td>83.149.9.216</td>
      <td>17/May/2015:10:05:12 +0000</td>
      <td>GET /presentations/logstash-monitorama-2013/pl...</td>
      <td>200</td>
      <td>7697</td>
      <td>http://semicomplete.com/presentations/logstash...</td>
      <td>Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1)...</td>
    </tr>
    <tr>
      <th>4</th>
      <td>83.149.9.216</td>
      <td>17/May/2015:10:05:07 +0000</td>
      <td>GET /presentations/logstash-monitorama-2013/pl...</td>
      <td>200</td>
      <td>2892</td>
      <td>http://semicomplete.com/presentations/logstash...</td>
      <td>Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1)...</td>
    </tr>
    <tr>
      <th>...</th>
      <td>...</td>
      <td>...</td>
      <td>...</td>
      <td>...</td>
      <td>...</td>
      <td>...</td>
      <td>...</td>
    </tr>
    <tr>
      <th>9995</th>
      <td>63.140.98.80</td>
      <td>20/May/2015:21:05:28 +0000</td>
      <td>GET /blog/tags/puppet?flav=rss20 HTTP/1.1</td>
      <td>200</td>
      <td>14872</td>
      <td>http://www.semicomplete.com/blog/tags/puppet?f...</td>
      <td>Tiny Tiny RSS/1.11 (http://tt-rss.org/)"</td>
    </tr>
    <tr>
      <th>9996</th>
      <td>63.140.98.80</td>
      <td>20/May/2015:21:05:50 +0000</td>
      <td>GET /blog/geekery/solving-good-or-bad-problems...</td>
      <td>200</td>
      <td>10756</td>
      <td>-</td>
      <td>Tiny Tiny RSS/1.11 (http://tt-rss.org/)"</td>
    </tr>
    <tr>
      <th>9997</th>
      <td>66.249.73.135</td>
      <td>20/May/2015:21:05:00 +0000</td>
      <td>GET /?flav=atom HTTP/1.1</td>
      <td>200</td>
      <td>32352</td>
      <td>-</td>
      <td>Mozilla/5.0 (compatible; Googlebot/2.1; +http:...</td>
    </tr>
    <tr>
      <th>9998</th>
      <td>180.76.6.56</td>
      <td>20/May/2015:21:05:56 +0000</td>
      <td>GET /robots.txt HTTP/1.1</td>
      <td>200</td>
      <td>-</td>
      <td>-</td>
      <td>Mozilla/5.0 (Windows NT 5.1; rv:6.0.2) Gecko/2...</td>
    </tr>
    <tr>
      <th>9999</th>
      <td>46.105.14.53</td>
      <td>20/May/2015:21:05:15 +0000</td>
      <td>GET /blog/tags/puppet?flav=rss20 HTTP/1.1</td>
      <td>200</td>
      <td>14872</td>
      <td>-</td>
      <td>UniversalFeedParser/4.2-pre-314-svn +http://fe...</td>
    </tr>
  </tbody>
</table>
</div>



## Analyzing data in DataFrame

Now that we have the data in Pandas DF we can investigate it in different ways. 

### Extract events by HTTP status code

We can, for example, extract all events where HTTP status code was 401 or 403.

Output of the below like statements are also shown directly as a graphical table within the Jupyter Notebook, so there is no need to define `print` statements.

```python
# Filter dataframe based on column STATUS
df[(df['STATUS'] == '403') | (df['STATUS'] == '401')]
```
(In Pandas `OR` / `AND` operators are `|` / `&`.)

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
      <th>IP</th>
      <th>DATE</th>
      <th>URL</th>
      <th>STATUS</th>
      <th>BYTES</th>
      <th>REFERRER</th>
      <th>UserAgent</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>3028</th>
      <td>94.153.9.168</td>
      <td>18/May/2015:11:05:47 +0000</td>
      <td>GET /presentations/vim/+++++++++++++++++++++++...</td>
      <td>403</td>
      <td>676</td>
      <td>http://www.semicomplete.com/presentations/vim/...</td>
      <td>Opera/9.80 (Windows NT 6.1; WOW64; U; ru) Pres...</td>
    </tr>
    <tr>
      <th>8685</th>
      <td>208.115.113.88</td>
      <td>20/May/2015:10:05:01 +0000</td>
      <td>GET /svnweb/xpathtool/ HTTP/1.1</td>
      <td>403</td>
      <td>305</td>
      <td>-</td>
      <td>Mozilla/5.0 (compatible; Ezooms/1.0; help@moz....</td>
    </tr>
  </tbody>
</table>
</div>




### Examine user agents

Below example extracts all unique user agents from the data.


```python
pd.DataFrame(df['UserAgent'].unique(), columns=['UserAgent'])
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
      <th>UserAgent</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1)...</td>
    </tr>
    <tr>
      <th>1</th>
      <td>Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:26....</td>
    </tr>
    <tr>
      <th>2</th>
      <td>Mozilla/5.0 (X11; Linux x86_64; rv:25.0) Gecko...</td>
    </tr>
    <tr>
      <th>3</th>
      <td>Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Ma...</td>
    </tr>
    <tr>
      <th>4</th>
      <td>Tiny Tiny RSS/1.11 (http://tt-rss.org/)"</td>
    </tr>
    <tr>
      <th>...</th>
      <td>...</td>
    </tr>
    <tr>
      <th>554</th>
      <td>Mozilla/4.0 (compatible; MSIE 5.0; Windows NT;...</td>
    </tr>
    <tr>
      <th>555</th>
      <td>Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US...</td>
    </tr>
    <tr>
      <th>556</th>
      <td>Mozilla/5.0 (Windows NT 5.0; rv:12.0) Gecko/20...</td>
    </tr>
    <tr>
      <th>557</th>
      <td>Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.3...</td>
    </tr>
    <tr>
      <th>558</th>
      <td>Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US...</td>
    </tr>
  </tbody>
</table>
</div>


This example shows top 10 user agents by occurances.

```python
pd.DataFrame(df['UserAgent'].value_counts()[:10].index, columns=['UserAgent'])
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
      <th>UserAgent</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <th>0</th>
      <td>Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKi...</td>
    </tr>
    <tr>
      <th>1</th>
      <td>Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1)...</td>
    </tr>
    <tr>
      <th>2</th>
      <td>UniversalFeedParser/4.2-pre-314-svn +http://fe...</td>
    </tr>
    <tr>
      <th>3</th>
      <td>Mozilla/5.0 (Windows NT 6.1; WOW64; rv:27.0) G...</td>
    </tr>
    <tr>
      <th>4</th>
      <td>Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Ma...</td>
    </tr>
    <tr>
      <th>5</th>
      <td>Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/53...</td>
    </tr>
    <tr>
      <th>6</th>
      <td>Mozilla/5.0 (compatible; Googlebot/2.1; +http:...</td>
    </tr>
    <tr>
      <th>7</th>
      <td>Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:27....</td>
    </tr>
    <tr>
      <th>8</th>
      <td>Mozilla/5.0 (X11; Linux x86_64; rv:27.0) Gecko...</td>
    </tr>
    <tr>
      <th>9</th>
      <td>Tiny Tiny RSS/1.11 (http://tt-rss.org/)"</td>
    </tr>
  </tbody>
</table>
</div>

