---
title: 'Investigating iPhone backups in Linux with libimobiledevice'
layout: 'post'
tags: ["iOS"]
---

This post shows how to use [libimobiledevice](https://libimobiledevice.org/) project's utils to backup an iPhone in Linux and then some simple investigation steps with those backups files.

## Installation

You can compile the tools from [source](https://github.com/libimobiledevice/libimobiledevice) or at least with Ubuntu you can find `libimobiledevice-utils` in *universe* reposotories and just install it with `apt`.

```
sudo apt install libimobiledevice-utils
```

## Taking a full backup

First, make a directory for backups:

```
$ mkdir ios-backups
```

Then just start the backup:

```
$ idevicebackup2 backup --full ios-backups/
```

Your iPhone will prompt and ask if you trust the device before it starts the backup.


## Investigating the backup files

Inside a backup all files are named with some sort of hash value instead of an actual file name. This means that you can't easily just start navigating through the files and see what is in there.

The `idevicebackup2` tool includes a command `unback` which would automatically sort and rename all the files, 
but it seems to have been broken for a while ([Github issue](https://github.com/libimobiledevice/libimobiledevice/issues/517)).

One comment on the issue mentions this:

> i think you dont need the unback functionality anymore, cause apple creates a Manifest.db file (during backup) which is simple sqlite file and there you have your files list with there names and relative path

You can open `Manifest.db` inside the backup directory and see that it has a table called `Files` which actually gives some necessary information to sort through the files.

```
$ cd ios-backups/<backup UUID>/
$ sqlite3 Manifest.db

sqlite> .tables
Files       Properties
sqlite> .schema
CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB);
CREATE INDEX FilesDomainIdx ON Files(domain);
CREATE INDEX FilesRelativePathIdx ON Files(relativePath);
CREATE INDEX FilesFlagsIdx ON Files(flags);
CREATE TABLE Properties (key TEXT PRIMARY KEY, value BLOB);
```

The `Properties` table was empty in my backups, but the `Files` seems to be the table that we should investigate. 

The fields I'm mostly interested inside the `Files` table seem to be:

* `fileID`: Name of the file inside the backup
* `Domain`: Sandobox the file is in
* `relativePath`: Relative path inside the domain


I know, for example, that there's a file `sms.db` which contains SMS messages. Let's check which file that is inside the backup:

```
sqlite> SELECT fileID from Files where relativePath LIKE '%sms.db%';
3d0d7e5fb2ce288813306e4d4636395e047a3d28
```

The backup is structured in directories based on the first two characters of the filename, so we are going to find this file under the directory `3d`.

```
$ file 3d/3d0d7e5fb2ce288813306e4d4636395e047a3d28 
3d/3d0d7e5fb2ce288813306e4d4636395e047a3d28: SQLite 3.x database, last written using SQLite version 3039005, writer version 2, read version 2, file counter 2, database pages 173, cookie 0x6d7, schema 4, UTF-8, version-valid-for 2
```

This is another SQLite file so we can just investigate it with `sqlite3` command as well.

```
$ sqlite3 3d/3d0d7e5fb2ce288813306e4d4636395e047a3d28

sqlite> .tables
_SqliteDatabaseProperties              message                              
attachment                             message_attachment_join              
chat                                   message_processing_task              
chat_handle_join                       recoverable_message_part             
chat_message_join                      sync_deleted_attachments             
chat_recoverable_message_join          sync_deleted_chats                   
deleted_messages                       sync_deleted_messages                
handle                                 unsynced_removed_recoverable_messages
kvtable                              
```

Let's check what the `message` table has:

```
sqlite> .schema
...
CREATE TABLE message (ROWID INTEGER PRIMARY KEY AUTOINCREMENT, guid TEXT UNIQUE NOT NULL, text TEXT, replace INTEGER DEFAULT 0, service_center TEXT, handle_id INTEGER DEFAULT 0, subject TEXT, country TEXT, attributedBody BLOB, version INTEGER DEFAULT 0, type INTEGER DEFAULT 0, service TEXT, account TEXT, account_guid TEXT, error INTEGER DEFAULT 0, date INTEGER, date_read INTEGER, date_delivered INTEGER, is_delivered INTEGER DEFAULT 0, is_finished INTEGER DEFAULT 0, is_emote INTEGER DEFAULT 0, is_from_me INTEGER DEFAULT 0, is_empty INTEGER DEFAULT 0, is_delayed INTEGER DEFAULT 0, is_auto_reply INTEGER DEFAULT 0, is_prepared INTEGER DEFAULT 0, is_read INTEGER DEFAULT 0, is_system_message INTEGER DEFAULT 0, is_sent INTEGER DEFAULT 0, has_dd_results INTEGER DEFAULT 0, is_service_message INTEGER DEFAULT 0, is_forward INTEGER DEFAULT 0, was_downgraded INTEGER DEFAULT 0, is_archive INTEGER DEFAULT 0, cache_has_attachments INTEGER DEFAULT 0, cache_roomnames TEXT, was_data_detected INTEGER DEFAULT 0, was_deduplicated INTEGER DEFAULT 0, is_audio_message INTEGER DEFAULT 0, is_played INTEGER DEFAULT 0, date_played INTEGER, item_type INTEGER DEFAULT 0, other_handle INTEGER DEFAULT 0, group_title TEXT, group_action_type INTEGER DEFAULT 0, share_status INTEGER DEFAULT 0, share_direction INTEGER DEFAULT 0, is_expirable INTEGER DEFAULT 0, expire_state INTEGER DEFAULT 0, message_action_type INTEGER DEFAULT 0, message_source INTEGER DEFAULT 0, associated_message_guid TEXT, associated_message_type INTEGER DEFAULT 0, balloon_bundle_id TEXT, payload_data BLOB, expressive_send_style_id TEXT, associated_message_range_location INTEGER DEFAULT 0, associated_message_range_length INTEGER DEFAULT 0, time_expressive_send_played INTEGER, message_summary_info BLOB, ck_sync_state INTEGER DEFAULT 0, ck_record_id TEXT, ck_record_change_tag TEXT, destination_caller_id TEXT, sr_ck_sync_state INTEGER DEFAULT 0, sr_ck_record_id TEXT, sr_ck_record_change_tag TEXT, is_corrupt INTEGER DEFAULT 0, reply_to_guid TEXT, sort_id INTEGER, is_spam INTEGER DEFAULT 0, has_unseen_mention INTEGER DEFAULT 0, thread_originator_guid TEXT DEFAULT NULL, thread_originator_part TEXT DEFAULT NULL, syndication_ranges TEXT DEFAULT NULL, was_delivered_quietly INTEGER DEFAULT 0, did_notify_recipient INTEGER DEFAULT 0, synced_syndication_ranges TEXT DEFAULT NULL, date_retracted INTEGER DEFAULT 0, date_edited INTEGER DEFAULT 0, was_detonated INTEGER DEFAULT 0, part_count INTEGER, is_stewie INTEGER DEFAULT 0, is_kt_verified INTEGER DEFAULT 0);
...
```

This table includes the actual messages and you can check the oldest message in the device with `select * from message LIMIT 1`.


## Automated sorting

Below is a simple script to sort the backup files based on the information in `Files` table of the `Manifest.db`.

```py
import sqlite3
import os
import sys
import shutil
import argparse


parser = argparse.ArgumentParser(description='Sort iOS backup made with idevicebackup2')
parser.add_argument('-p','--path', help='Path to backup file with Manifest.db', required=True)
args = parser.parse_args()

path = os.path.join(args.path, "Manifest.db")

if not os.path.isfile(path):
    print(f"Could not find path: {path}")
    sys.exit(1)

connection = sqlite3.connect(f"{args.path}Manifest.db")
cursor = connection.cursor()
rows = cursor.execute("select fileID,relativePath,domain from Files").fetchall()
for row in rows:
    src = os.path.join(args.path, row[0][:2]+'/'+row[0])
    dest = row[2] + '/' + row[1]
    if os.path.isfile(src) and dest.strip() != '' :
        print('/'.join(dest.split('/')[:-1]))
        os.makedirs('unpacked/' + '/'.join(dest.split('/')[:-1]), exist_ok=True)
        print('unpacked/' + dest)
        shutil.copy(src, 'unpacked/' + dest)
connection.close()

```

You run the script like this:

```
python3 script.py -p path-to/ios-backups/<backup UUID>/
```

It will create a directory named `unpacked` where it copies all the files it could. For example, the `sms.db` file:

```
$ find unpacked/ -name "sms.db"
unpacked/HomeDomain/Library/SMS/sms.db
```

Note that the script doesn't do anything with files that have an empty `relativePath` field. 
This is merely a PoC and you will most definetly find better tools with a simple web search, but it's sometimes fun to write something quick and dirty yourself. 


## Other tips and tricks

### Analyzing binary plists files

Inside the backup you will find lots of files that are type of `Apple binary property list`. You can convert these files to XML using `plistutil` command.

```
$ sudo apt-get install libplist-utils
$ plistutil -i ./HomeDomain/Library/DeviceRegistry.state/historySecureProperties.plist -o ./HomeDomain/Library/DeviceRegistry.state/historySecureProperties.plist.xml
```

### Browser history

If the device happens to have Firefox you can check its history from `browser.db` file. Example query:

```
sqlite> select url,title from history;
```

### Export SMS messages to csv

```
sqlite3 -header -csv ./HomeDomain/Library/SMS/sms.db "select datetime(substr(date, 1, 9) + 978307200, 'unixepoch', 'localtime') as date,account,text from message" >sms.csv
```

Set correct path to `sms.db` file.

### WIFI information

Check file `RootDomain/Library/Preferences/wifid.plist`.

### Camera data

Check files under `CameraRollDomain` domain.

### Address book

Check file `HomeDomain/Library/AddressBook/AddressBook.sqlitedb`.

### Other libimobiledevice utils

Libimobiledevice also has other utils that might interest you. For example:

* `ideviceinfo` gets basic information of the device
* `idevicename` gets or sets the device name.
* `idevicesyslog` allows to dump the device's syslog.


## Automated parsing with iLEAPP

There's a nice tool called iLEAPP that can parse full images taken from a jailbroken iPhone and backups taken with itunes or `idevicebackup2`.
It produces HTML report that contains all the information it was able to get from the image or backup. You can find the project here: [https://github.com/abrignoni/iLEAPP](https://github.com/abrignoni/iLEAPP).
