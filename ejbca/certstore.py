#
# Python modules for select EJBCA Certificate Store (RFC-4387) API's
#

import os
import sys

from typing import Optional

import urllib3

import base64
import codecs

import ejbca

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

# not sure why "import .helpers" doesn't work here
import ejbca.helpers as helpers
from ejbca.helpers import eprint as eprint

def _ldap_canonicalize(dn: x509.Name) -> x509.Name:
    # prefered DN order of OIDs for generating hashed DER
    ordered = [
        x509.NameOID.COUNTRY_NAME,
        x509.NameOID.ORGANIZATION_NAME,
        x509.NameOID.COMMON_NAME,
    ]

    # convert dn to dictionary of oid/value pairs
    d = { a.oid: a.value for a in dn }

    attrs = []
    for oid in ordered:
        if oid in d:
            attrs.append(
                x509.NameAttribute(oid, d[oid])
            )

    dn = x509.Name(attrs)

    return dn

def _search_url() -> str:
    return 'http://' + ejbca.server.name + '/ejbca/publicweb/certificates/search.cgi?sHash={ihash:s}'

def search_subject(
        dn: x509.Name,
        ldap_order: Optional[bool] = False,
    ) -> x509.Certificate:

    # re-order DN in canonical order...
    if ldap_order:
        dn = _ldap_canonicalize(dn)

    der = dn.public_bytes()
    digest = hashes.Hash(hashes.SHA1())
    digest.update(der)
    hash = digest.finalize()

    pem = base64.b64encode(hash)

    # drop '=' padding
    pem = pem[0:27]

    url = _search_url().format(ihash = pem.decode())

    http = urllib3.PoolManager()

    if ejbca.tracing:
        eprint('GET {0:s}\n'.format(helpers.localurl(url)))

    req = http.request(
        'GET',
        url,
        timeout = urllib3.Timeout(connect = 1.0),
        retries = False,
    )

    ### return value is binary
    ##if ejbca.tracing:
    ##    helpers.dump(req)

    if req.status != 200:
        ##if not ejbca.tracing:
        ##    helpers.dump(req)
        raise RuntimeError('Certificate fetch (cert-store) failure')

    data = req.data

    cert = x509.load_der_x509_certificate(data)

    return cert

