#
# Python modules for select EJBCA EST API's
#

import os
import sys

from typing import Tuple, Optional, Union

import urllib3

import base64

import ejbca

# not sure why "import .helpers" doesn't work here
import ejbca.helpers as helpers
from ejbca.helpers import eprint as eprint

def _simpleenroll_url() -> str:
    return 'https://' + ejbca.server.name + '/.well-known/est/' + ejbca.server.alias + '/simpleenroll'

def simple_enroll(
        csr: bytes,
        creds: ejbca.Creds,
        url: Optional[bytes] = None,
    ) -> bytes:

    if url is None:
        url = _simpleenroll_url()
    else:
        url = url.decode()

    http = urllib3.PoolManager(
        cert_reqs = "CERT_REQUIRED" if creds.secure else "CERT_NONE",
        ca_certs = creds.bundle,
        # client side creds are ignored
    )

    headers = {
        'Accept': 'application/pkcs7-mime; smime-type=certs-only',
        'Content-Type': 'application/pkcs10',
        'Content-Transfer-Encoding': 'base64',
    }

    if ejbca.tracing:
        eprint('POST {0:s}'.format(helpers.localurl(url)))
        for hdr in headers.keys():
            eprint('{0:s}: {1:s}'.format(hdr, headers[hdr]))
        eprint('\n{0:s}'.format(csr.decode()))

    req = http.request(
        'POST',
        url,
        body = csr,
        headers = headers,
        timeout = urllib3.Timeout(connect = 1.0),
        retries = False,
    )

    if ejbca.tracing:
        helpers.dump(req)

    if req.status != 200:
        if not ejbca.tracing:
            helpers.dump(req)
        raise RuntimeError('Enrollment (EST) failure')

    data = req.data

    # strip newlines
    data = data.replace(b'\n', b'')

    return data

def _cacerts_url() -> str:
    return 'https://' + ejbca.server.name + '/.well-known/est/' + ejbca.server.alias + '/cacerts'

def ca_certs(creds: ejbca.Creds) -> bytes:

    url = _cacerts_url()

    http = urllib3.PoolManager(
        cert_reqs = "CERT_REQUIRED" if creds.secure else "CERT_NONE",
        ca_certs = creds.bundle,
        # client side creds are ignored
    )

    headers = {
        'Accept': 'application/pkcs7-mime',
        'Content-Type': 'application/pkcs7-mime',
        'Content-Transfer-Encoding': 'base64',
    }

    if ejbca.tracing:
        eprint('GET {0:s}'.format(helpers.localurl(url)))
        for hdr in headers.keys():
            eprint('{0:s}: {1:s}'.format(hdr, headers[hdr]))

    req = http.request(
        'GET',
        url,
        headers = headers,
        timeout = urllib3.Timeout(connect = 1.0),
        retries = False,
    )

    if ejbca.tracing:
        helpers.dump(req)

    if req.status != 200:
        if not ejbca.tracing:
            helpers.dump(req)
        raise RuntimeError('CA certificate fetch failure')

    data = req.data

    # strip newlines
    data = data.replace(b'\n', b'')

    return data

