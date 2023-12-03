---
title: 'Use Hashcat to get password of Veracrypt hidden volume'
layout: 'post'
tags: ["Security"]
---
{:toc}

This post shows how to use Hashcat to crack password of hidden volume inside a Veracrypt container. I assume you know what Veracrypt is and what it can be used for if you are interested in this.
  
First, create a container with a hidden volume using Veracrypt. I'm using `/tmp/test.vc` container in my examples. With hashcat I'm using mode 13752 (`-m <mode>`), but you need to change that to match your volume's settings. 
Here is some reference for the modes: [https://hashcat.net/wiki/doku.php?id=example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes).
  
Then we start cracking:

* Create a file name `wordlist` and add both passwords in it.
* Execute hashcat (remember to set the correct mode and path to your container):
  
```
hashcat -m 13752 -a 0 /tmp/test.vc wordlist
```
  
This should find the password for the outer (non-hidden) volume.
  
* Next we need to copy 512 bytes from the container, but skip the first 64 kilobytes:
  
```
dd if=/tmp/test.vc skip=64K bs=1 count=512 of=new.vc
```
  
* Execute hashcat again, but against the created `new.vc`:
  
```
hashcat -m 13751 -a 0 new.vc wordlist
```
  
This should find the password for the inner (hidden) container.
