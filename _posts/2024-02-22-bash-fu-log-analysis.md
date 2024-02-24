---
title: '(Bash|Grep)-Fu Log Analysis'
layout: 'post'
tags: ["Security", "LogAnalysis"]
---
{:toc}

In the [last post](/2024/02/21/pandas-log-analysis.html) I showed how to use Pandas library to parse Apache logs. While that can be really powerful way to analyze some log data it sometimes is just easier and quicker to do some direct Bash-Fu. 

I'm using the same [sample Apache log file](https://github.com/elastic/examples/blob/master/Common%20Data%20Formats/apache_logs/apache_logs) from Elastic's Github repository, and will show some quick examples of how basic *nix tools (mostly grep) can be used to do some quick log analysis.

## Example analysis commands

Below is an example line from the sample file to use as a reference for the commands.

```sh
83.149.9.216 - - [17/May/2015:10:05:03 +0000] "GET /presentations/logstash-monitorama-2013/images/kibana-search.png HTTP/1.1" 200 203023 "http://semicomplete.com/presentations/logstash-monitorama-2013/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1700.77 Safari/537.36"
```

### Get the total amount of events

Just to know how much data we have.

```sh
$ wc -l sample_logs
```

### Get list of IP addresses

```sh
$ grep -Po '^(\d+\.){3}\d+' apache_logs |sort -u
100.2.4.116
100.43.83.137
101.119.18.35
101.199.108.50
101.226.168.196
101.226.168.198
101.226.33.222
103.245.44.13
103.247.192.5
103.25.13.22
...
```

### See how many events per IP

```sh
$ grep -Po '^(\d+\.){3}\d+' apache_logs | uniq -c | sort -nr
     97 75.97.9.59
     89 130.237.218.86
     85 130.237.218.86
     50 75.97.9.59

...
```

97,89, etc. is the amount of how many times that IP is found from the logs.

### Get all events with status code 401 or 403

```sh
$ grep -P '"\s\K(401|403)\s' apache_logs 
94.153.9.168 - - [18/May/2015:11:05:47 +0000] "GET /presentations/vim/+++++++++++++++++++++++++++++++++++Result:+%E8%F1%EF%EE%EB%FC%E7%EE%E2%E0%ED+%ED%E8%EA%ED%E5%E9%EC+%22newkoversjup%22;+ReCaptcha+%E4%E5%F8%E8%F4%F0%EE%E2%E0%ED%E0;+%28JS%29;+%E7%E0%F0%E5%E3%E8%F1%F2%F0%E8%F0%EE%E2%E0%EB%E8%F1%FC;+%ED%E5+%ED%E0%F8%EB%EE%F1%FC+%F4%EE%F0%EC%FB+%E4%EB%FF+%EE%F2%EF%F0%E0%E2%EA%E8;+Result:+%EE%F8%E8%E1%EA%E0:+%22i+never+really+liked+c%27s+assert%28%29+feature.+if+an+assertion+is+violated,+it%27lltell+you+what+assertion+failed+but+completely+lacks+any+context:%22;+%ED%E5+%ED%E0%F8%EB%EE%F1%FC+%F4%EE%F0%EC%FB+%E4%EB%FF+%EE%F2%EF%F0%E0%E2%EA%E8; HTTP/1.0" 403 676 "http://www.semicomplete.com/presentations/vim/+++++++++++++++++++++++++++++++++++Result:+%E8%F1%EF%EE%EB%FC%E7%EE%E2%E0%ED+%ED%E8%EA%ED%E5%E9%EC+%22newkoversjup%22;+ReCaptcha+%E4%E5%F8%E8%F4%F0%EE%E2%E0%ED%E0;+%28JS%29;+%E7%E0%F0%E5%E3%E8%F1%F2%F0%E8%F0%EE%E2%E0%EB%E8%F1%FC;+%ED%E5+%ED%E0%F8%EB%EE%F1%FC+%F4%EE%F0%EC%FB+%E4%EB%FF+%EE%F2%EF%F0%E0%E2%EA%E8;+Result:+%EE%F8%E8%E1%EA%E0:+%22i+never+really+liked+c%27s+assert%28%29+feature.+if+an+assertion+is+violated,+it%27lltell+you+what+assertion+failed+but+completely+lacks+any+context:%22;+%ED%E5+%ED%E0%F8%EB%EE%F1%FC+%F4%EE%F0%EC%FB+%E4%EB%FF+%EE%F2%EF%F0%E0%E2%EA%E8;" "Opera/9.80 (Windows NT 6.1; WOW64; U; ru) Presto/2.10.289 Version/12.01"
208.115.113.88 - - [20/May/2015:10:05:01 +0000] "GET /svnweb/xpathtool/ HTTP/1.1" 403 305 "-" "Mozilla/5.0 (compatible; Ezooms/1.0; help@moz.com)"
```

### Get list of all status codes

```sh
$ grep -oP '"\s\K\d{3}\s' apache_logs |sort -u
200 
206 
301 
304 
403 
404 
416 
500 
```

### Get user agents 

(sorted first 12)

```sh
$ grep -oP '"\s":?\K.*"$' apache_logs |tr -d '"'|sort -u|head -n 12
-
&as_qdr=all
Baiduspider-image+(+http://www.baidu.com/search/spider.htm)
binlar_2.6.3 test@mgmt.mic
binlar_2.6.3 (test@mgmt.mic)
Chef Client/10.18.2 (ruby-1.9.3-p327; ohai-6.16.0; x86_64-linux; +http://opscode.com)
CommaFeed/1.0 (http://www.commafeed.com)
curl/7.22.0 (i686-pc-linux-gnu) libcurl/7.22.0 OpenSSL/1.0.1 zlib/1.2.3.4 libidn/1.23 librtmp/2.3
Dalvik/1.6.0 (Linux; U; Android 4.1.2; C2105 Build/15.0.A.2.17)
Dalvik/1.6.0 (Linux; U; Android 4.1.2; GT-I8190 Build/JZO54K)
Dalvik/1.6.0 (Linux; U; Android 4.1.2; GT-I8552 Build/JZO54K)
Dalvik/1.6.0 (Linux; U; Android 4.1.2; GT-S5282 Build/JZO54K)
```

### List all request

```sh
$ grep -oP '\]\s"\K.*?"' apache_logs |tr -d '"'
GET /presentations/logstash-monitorama-2013/images/kibana-search.png HTTP/1.1
GET /presentations/logstash-monitorama-2013/images/kibana-dashboard3.png HTTP/1.1
GET /presentations/logstash-monitorama-2013/plugin/highlight/highlight.js HTTP/1.1
GET /presentations/logstash-monitorama-2013/plugin/zoom-js/zoom.js HTTP/1.1
GET /presentations/logstash-monitorama-2013/plugin/notes/notes.js HTTP/1.1
GET /presentations/logstash-monitorama-2013/images/sad-medic.png HTTP/1.1
...
```

### Get all request methods

```sh
$ grep -oP '\]\s"\K.*?"' apache_logs |awk '{print $1}'|sort -u
GET
HEAD
OPTIONS
POST
```

## Hunt for interesting events

Here is some examples to "hunt" for some interesting log events.

Note the `grep -i` usage in these examples which makes the grep queries case-insensitive as the targeted data can many times be upper or lower case.

You can search for pre-made regex patterns for many things, but I usually like to start with quite a "wide" pattern.
It might catch some false positives first, but I can fine tune the pattern from there.
Pre-made complex regex patterns can easily miss something because of different regex flavors and such.

Note that these examples are mainly meant to find things from the request URLs in Apache's or other similar applications' logs. 
You might want extract request URLs first and run searches against that file. For example:

```sh
$ grep -oP '\]\s"\K.*?"' apache_logs |tr -d '"' > requests.txt
```

When you find something interesting you can select some keywords to search for the full log lines within the original file.

### Search for SQL injection attempts

```sh
$ grep -iP "select|union|drop|(or\s.+=.+)" --color apache_logs
```

### Search for XSS attempts

```sh
$ grep -iP 'script(\>|%3E).*(\<\/|%3C%2F)script' --color apache_logs
```

### Search for Linux injection stuff

```sh
$ grep -iP 'passwd|shadow|\.\.(\/|%2F)' --color apache_logs
```

Below example first greps the request URL and tries to find command injection chains based on `;`, `&&` and `||` characters.

```sh
$ grep -oP '\]\s"\K.*?"' apache_logs |tr -d '"'| grep -P '.*(&&|;|\|\|).*(&&|;|\|\|).*' --color
```

No need to do the first grep (+ `tr`) if you first create the file with only the request URLs. For example:

```sh
grep -P '.*(&&|;|\|\|).*(&&|;|\|\|).*' --color requests.txt
```

### Search for JWT tokens

```sh
$ grep -iP 'eyj.+\..+\..+' --color apache_logs
```

### Search for hex-encoded characters

```sh
$ grep '\\x..\\' --color apache_logs
```

### Combine everything

Grep doesn't support `-f <pattern file` with the `-P` option, but you can still add patterns to a file and test all of those automatically.

One way to do this is by reading the pattern file line by line and passing that to grep command.

```sh
while IFS= read -r line; do grep --color -Pi $line sample.log;done < patterns.txt
```
