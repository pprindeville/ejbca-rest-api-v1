#
# Python modules for select EJBCA REST API's
#

import os
import sys

from typing import Tuple, Optional, Union

import urllib3

import datetime
import json

import ejbca

# not sure why "import .helpers" doesn't work here
import ejbca.helpers as helpers
from ejbca.helpers import eprint as eprint

def _cert_url() -> str:
    return 'https://' + ejbca.server.name + '/ejbca/ejbca-rest-api/v1/ca/{subject_dn:s}/certificate/download'

def getcert(
        subject: bytes,
        creds: ejbca.Creds,
    ) -> bytes:

    # rewrite the subject using %-encoding
    subject = helpers.quote(subject)

    url = _cert_url().format(subject_dn = subject)

    http = urllib3.PoolManager(
        cert_reqs = "CERT_REQUIRED" if creds.secure else "CERT_NONE",
        ca_certs = creds.bundle,
        cert_file = creds.cert,
        key_file = creds.key,
    )

    if ejbca.tracing:
        eprint('GET {0:s}'.format(helpers.localurl(url)))

    req = http.request(
        'GET',
        url,
        timeout = urllib3.Timeout(connect = 1.0),
        retries = False,
    )

    if ejbca.tracing:
        helpers.dump(req)

    if req.status != 200:
        if not ejbca.tracing:
            helpers.dump(req)
        raise RuntimeError

    data = req.data

    return data

def _revocation_url() -> str:
    return  'https://' + ejbca.server.name + '/ejbca/ejbca-rest-api/v1/certificate/{issuer_dn:s}/{cert_sn:x}/revocationstatus'

def getcertstatus(
        issuer: bytes,
        serial: int,
        creds: ejbca.Creds,
    ) -> Tuple[bool, Optional[str], Optional[datetime.datetime], Optional[str]]:

    # rewrite the issuer using %-encoding
    issuer = helpers.quote(issuer)

    url = _revocation_url().format(issuer_dn = issuer, cert_sn = serial)

    http = urllib3.PoolManager(
        cert_reqs = "CERT_REQUIRED" if creds.secure else "CERT_NONE",
        ca_certs = creds.bundle,
        cert_file = creds.cert,
        key_file = creds.key,
    )

    if ejbca.tracing:
        eprint('GET {0:s}'.format(helpers.localurl(url)))

    req = http.request(
        'GET',
        url,
        timeout = urllib3.Timeout(connect = 1.0),
        retries = False,
    )

    if ejbca.tracing:
        helpers.dump(req)

    if req.status != 200:
        if not ejbca.tracing:
            helpers.dump(req)
        raise RuntimeError

    data = req.data
    resp = json.loads(data)

    revoked = resp['revoked']

    # Other fields aren't present if revoked isn't True
    if not revoked:
        return False, None, None, None

    reason = resp['revocation_reason']
    date = resp['revocation_date']
    date = helpers.parse_ts(date)
    message = resp['message']

    return revoked, reason, date, message

def _end_entity_url() -> str:
    return 'https://' + ejbca.server.name + '/ejbca/ejbca-rest-api/v1/endentity'

def add_end_entity(
        username: bytes,
        password: bytes,
        subject: bytes,
        ca_name: bytes,
        cert_profile_name: bytes,
        end_entity_profile_name: bytes,
        creds: ejbca.Creds,
        token: str = "P12",
        san: Optional[bytes] = None,
        email: Optional[bytes] = None,
        extensions: Optional[dict] = None,
    ) -> None:

    url = _end_entity_url()

    d = {
        'username': username.decode(),
        'password': password.decode(),
        'subject_dn': subject.decode(),
        'ca_name': ca_name.decode(),
        'certificate_profile_name': cert_profile_name.decode(),
        'end_entity_profile_name': end_entity_profile_name.decode(),
        'token': token,
    }

    if extensions is None:
        extensions = {}

    # clone dictionary, converting bytes to strings
    extensions2 = {}
    for key in extensions:
        value = extensions[key]
        if isinstance(value, bytes):
           value = value.decode()
        if isinstance(key, bytes):
           key = key.decode()
        extensions2[key] = value

    if not san is None:
        d['subject_alt_name'] = san.decode()
    if not email is None:
        d['email'] = email.decode()
    if not extensions is None:
        d['extensions_data'] = extensions2

    data = json.dumps(d)

    http = urllib3.PoolManager(
        cert_reqs = "CERT_REQUIRED" if creds.secure else "CERT_NONE",
        ca_certs = creds.bundle,
        cert_file = creds.cert,
        key_file = creds.key,
    )

    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }

    if ejbca.tracing:
       eprint('POST {0:s}\n'.format(helpers.localurl(url)))
       for hdr in headers:
           eprint('{0:s}: {1:s}'.format(hdr, headers[hdr]))
       eprint('\n{0:s}'.format(data))

    req = http.request(
        'POST',
        url,
        body = data.encode(),
        headers = headers,
        timeout = urllib3.Timeout(connect = 1.0),
        retries = False,
    )

    if ejbca.tracing:
        helpers.dump(req)

    if req.status != 200:
        if not ejbca.tracing:
            helpers.dump(req)
        raise RuntimeError

    data = req.data

def _end_entity_url2() -> str:
    return 'https://' + ejbca.server.name + '/ejbca/ejbca-rest-api/v1/endentity/{username:s}'

def delete_end_entity(
        username: bytes,
        creds: ejbca.Creds,
    ) -> None:

    url = _end_entity_url2().format(username = username.decode())

    http = urllib3.PoolManager(
        cert_reqs = "CERT_REQUIRED" if creds.secure else "CERT_NONE",
        ca_certs = creds.bundle,
        cert_file = creds.cert,
        key_file = creds.key,
    )

    if ejbca.tracing:
       eprint('DELETE {0:s}'.format(helpers.localurl(url)))

    req = http.request(
        'DELETE',
        url,
        timeout = urllib3.Timeout(connect = 1.0),
        retries = False,
    )

    if ejbca.tracing:
        helpers.dump(req)

    if req.status != 200:
        if not ejbca.tracing:
            helpers.dump(req)
        raise RuntimeError

def _enroll_keystore_url() -> str:
    return 'https://' + ejbca.server.name + '/ejbca/ejbca-rest-api/v1/certificate/enrollkeystore'

def enroll_keystore(
        username: bytes,
        password: bytes,
        key_alg: bytes,
        key_spec: bytes,
        creds: ejbca.Creds,
    ) -> Tuple[bytes, bytes]:

    url = _enroll_keystore_url()

    http = urllib3.PoolManager(
        cert_reqs = "CERT_REQUIRED" if creds.secure else "CERT_NONE",
        ca_certs = creds.bundle,
        cert_file = creds.cert,
        key_file = creds.key,
    )

    d = {
        'username': username.decode(),
        'password': password.decode(),
        'key_alg': key_alg.decode(),
        'key_spec': key_spec.decode(),
    }

    data = json.dumps(d)

    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }

    if ejbca.tracing:
        eprint('POST {0!s}\n'.format(helpers.localurl(url)))
        for hdr in headers:
            eprint('{0:s}: {1:s}'.format(hdr, headers[hdr]))
        eprint('\n{0:s}'.format(data))

    req = http.request(
        'POST',
        url,
        headers = headers,
        body = data.encode(),
        timeout = urllib3.Timeout(connect = 1.0),
        retries = False,
    )

    if ejbca.tracing:
        helpers.dump(req)

    if req.status != 201:
        if not ejbca.tracing:
            helpers.dump(req)
        raise RuntimeError

    data = req.data

    if ejbca.tracing:
       eprint(data)

    resp = json.loads(data)

    certificate = resp['certificate'].encode()
    format = resp['response_format'].encode()

    return format, certificate
