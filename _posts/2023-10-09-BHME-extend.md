---
title: Extend (Forensics)
author: pcb
date: 2023-10-08 20:30:00 +0500
categories: [CTF Events, Blackhat MEA 2023]
tags: [forensics]
math: true
mermaid: true
image:
  path: https://i.imgur.com/fDDlPRz.png
  alt: 

---


![chall](https://i.imgur.com/VIxrGrA.png)
In a challenge file, I encountered an anime image. Upon inspecting the image, I used ExifTool and discovered a comment containing a link: [https://justuser-tmpusage.github.io/BHatCtf.github.io/](https://justuser-tmpusage.github.io/BHatCtf.github.io/)

![exiftool](https://i.imgur.com/XhX9e5l.png)

I visited the webpage and found it to be the actual briefing for the challenge.

![webpage](https://i.imgur.com/1Ex1xrz.png)

Towards the end of the page, it mentioned, "find more data somewhere here." To start, I examined the source code and navigated to its GitHub repo, discovering additional details in the fulldata.md file.

![git1](https://i.imgur.com/zWafLCs.png)
![git2](https://i.imgur.com/YCrpKlS.png)
The "more data here" anchor tag redirected me to a Pastebin where I found some credentials, indicating that only the mega.nz link would work.

![pastebin](https://i.imgur.com/nBFJe9C.png)
After visiting the mega.nz drive link and unlocking it using the decryption key, I found a Google.7z file.

![meganz](https://i.imgur.com/zg39zjA.png)
## Real Challenge files
Upon downloading and unzipping the file, it seemed like the real challenge began. I obtained a Chrome userdata folder for the user "jacksmp."

![google7z](https://i.imgur.com/Y9Ka1fc.png)
![structure](https://i.imgur.com/ueRK3dO.png)
The challenge, as stated on the briefing webpage, was to identify the reason behind the compromise of jacksmp's personal data. Initially, I examined the history, bookmarks, and cache, but found no useful information.

Attempting to grep directly for the flag "BHflagy{}" and also converting it to base64. 
![base64](https://i.imgur.com/dk7pUgy.png)
From the analysis, I speculated that 'Qkh' could be more relevant:

```bash
find . -type f -exec strings {} \; | grep -i 'Qkh'
```
However, all grepping attempts failed to find the flag.

Turning attention to the extensions folder, I noticed seven extensions, suggesting potential suspicious activity. I opened VSCode in that directory to navigate through each extension's source code.

![extensions](https://i.imgur.com/ZhHXiOV.png)
![vscode](https://i.imgur.com/6gyz9Xb.png) 
Some extension names seemed suspicious, but one extension code stands out due to obfuscated code—a clear violation of Chrome Web Store policies.
![maliciousextension](https://i.imgur.com/KndMYTt.png)
![chromepolicy](https://i.imgur.com/ZdH6Ntu.png) 
Now, the focus shifted to deobfuscation since it was evident that this extension was the reason for the compromise.

## Deobfuscation of malicious extension
First, I beautified the JavaScript code:

![prettify](https://i.imgur.com/VRCncyF.png)
Then, I examined the function returning the array of words, simplifying it for better understanding:

![arrayfunction](https://i.imgur.com/aNj47fV.png)
![simplify](https://i.imgur.com/7ZkoiER.png)

The first function performed hex subtraction on its argument, returning the value of the main array.
I simplified it, , assigning the name "**randarr**" for my convenience (it's not random), and loaded both(retarray & randarr) into my browser console (this isn't malicious) simply to facilitate the retrieval of those values through function calls.

![randfunction](https://i.imgur.com/TUcHJBp.png)
![simplify2](https://i.imgur.com/yUhKMlK.png) 
![devtools](https://i.imgur.com/bc2ucId.png)
The self-invoking function, following the initial function, is accountable for altering the position of elements within the array.
![changingoffset](https://i.imgur.com/pdfovhu.png)
Essentially, the code snippet below removes the first character from the array and appends it at the end. I couldn't determine the exact number of iterations for this loop, so I devised an alternative approach.
```javascript
_0x55ac68['push'](_0x55ac68['shift']());
```

Checking the ``domag()`` function and ``document[_0x52c4ab(0x19b)]``:

![domagfun](https://i.imgur.com/frY97ka.png)
I utilized the randarr loaded function to retrieve the value from the array. If it didn't match the name of the document method, I determined the position of that word and then identified the document method, that could accept a string argument, from the main array. Subsequently, after finding that, I located its index and measured the distance from the incorrect word to that method name.
```javascript
_0xe7653c = document[_0x52c4ab(0x19b)](_0x52c4ab(0x192)),
_0x2307c4 = document[_0x52c4ab(0x19b)](_0x52c4ab(0x1b1)),
_0x42cb77 = document[_0x52c4ab(0x19b)]('username'),
_0x22bc84 = document[_0x52c4ab(0x19b)](_0x52c4ab(0x19d));
```
![calculation](https://i.imgur.com/bmePOBy.png)
create a new array and execute the command ``new_array['push'](new_array['shift']())`` eight times; alternatively, a for loop can be employed. Following this step, ensure that the index of 'getElementsByName' aligns with our previously identified incorrect word index.
![newarray](https://i.imgur.com/NCbzamE.png)
Subsequently, replace that array with the array in the retarray function and reload to facilitate the deobfuscation process. After this step, everything started to fall into place, and I successfully deobfuscated the domag function.


![deobfuscatestart](https://i.imgur.com/wPMaK0l.png)
![deobfuscateddomag](https://i.imgur.com/Rlx9Jtc.png)

Now, after deobfuscating the connect function, I obtained a WebSocket URL.

![obfuscatedconnect](https://i.imgur.com/TjOnCAX.png)
![deobfuscatedconnect](https://i.imgur.com/233Qzl7.png)
```plaintext
wss://Qf2MjYwAzNyIDOjVTZkJTY---1QjY0YGNxEDM1cTMxQ2YjV---WYwIjYzMTM2sXWHFETGhkQ.oast.pro/
```
Although my attempt to establish a connection with the WebSocket yielded no response, a more thorough examination of the URL jogged my memory about '**Qkh**' I noticed it was written in reverse. Subsequently, I reversed the base64-encoded text and decoded it, revealing the flag.
![flag](blob:https://imgur.com/98468779-0d81-4e5d-8d20-7d29646a82f4) 
> Show some support by following me on [Github](https://github.com/PakCyberbot)
{: .prompt-tip }