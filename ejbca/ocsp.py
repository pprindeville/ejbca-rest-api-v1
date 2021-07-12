#
# Python modules for EJBCA OCSP service
#

import os
import sys

import typing

import urllib3

import base64

import ejbca

# not sure why "import .helpers" doesn't work here
import ejbca.helpers as helpers
from ejbca.helpers import eprint as eprint

from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives import serialization, hashes

def _ocsp_status_url() -> str:
    return 'http://' + ejbca.server.name + '/ejbca/publicweb/status/ocsp'

def _create_ocsp_req(cert: x509.Certificate, issuer: x509.Certificate) -> ocsp.OCSPRequest:
    builder = ocsp.OCSPRequestBuilder().add_certificate(
        cert, issuer, hashes.SHA256(),
    )
    return builder.build()

def getocspstatus(cert: x509.Certificate, issuer: x509.Certificate) -> ocsp.OCSPCertStatus:
    ocsp_req = _create_ocsp_req(cert, issuer)
    der = ocsp_req.public_bytes(serialization.Encoding.DER)
    pem = base64.b64encode(der)

    http = urllib3.PoolManager()

    url = _ocsp_status_url() + '/' + pem.decode()

    headers = {
        'Content-Type': 'application/ocsp-request',
    }

    if ejbca.tracing:
       eprint('GET {0:s}'.format(helpers.localurl(url)))
       for hdr in headers.keys():
           eprint('{0:s}: {1:s}'.format(hdr, headers[hdr]))
       eprint('\n')

    req = http.request(
        'GET',
        url,
        headers = headers,
        timeout = urllib3.Timeout(connect = 1.0),
        retries = False,
    )

    ## result is binary, so don't dump it
    ## if ejbca.tracing:
    ##     helpers.dump(req)

    if req.status != 200:
        if not ejbca.tracing:
            helpers.dump(req)
        raise RuntimeError('Failure getting certificate status (OCSP)')

    der = req.data
    ocsp_resp = ocsp.load_der_ocsp_response(der)

    if ocsp_resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        helpers.dump(req)
        raise RuntimeError('Unsuccessful OCSP query')

    return ocsp_resp.certificate_status

