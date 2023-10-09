---
title: Not supported (Forensics)
author: pcb
date: 2023-10-08 20:20:00 +0500
categories: [CTF Events, Blackhat MEA 2023]
tags: [forensics]
math: true
mermaid: true
image:
  path: https://i.imgur.com/fDDlPRz.png
  alt: 

---
![challenge](https://i.imgur.com/yH2OFBK.png)
The challenge was quite straightforward(mentioned in the challenge); it involved a memory dump file. Initially, I listed the running processes and identified the Notepad process, copying its PID:

```bash
vol -f memdump.mem windows.pslist.PsList
```
Subsequently, I dumped the content of that process:

```bash
vol -f memdump.mem windows.memmap.Memmap --pid 6028 --dump 
```
Upon conducting some online research, I discovered that Notepad data stores in little-endian format:
```
strings -e l pid.6028.dmp| grep -in 'bhf' 
```
![flag](https://i.imgur.com/lV3rEjw.png)




> Show some support by following me on [Github](https://github.com/PakCyberbot)
{: .prompt-tip }