#!/usr/bin/env python
# -*- coding: utf-8 -*-


import json
from ssl import PEM_cert_to_DER_cert

import jwt
from tornado.httpclient import AsyncHTTPClient
from tornado.escape import to_unicode
from Crypto.Util.asn1 import DerSequence
from Crypto.PublicKey import RSA


class GoogleIdToken:
    _GOOGLE_CERTS_URI = 'https://www.googleapis.com/oauth2/v1/certs'
    _GOOGLE_ISS_URI = 'accounts.google.com'

    def __init__(self, jwt):
        self._jwt = jwt
        self.token = None

    def is_valid(self, res, aud, iss=_GOOGLE_ISS_URI):
        certs = json.loads(to_unicode(res.body))
        for pem in certs.values():
            try:
                token = jwt.decode(self._jwt, key=self._get_pubkey(pem))
            except (jwt.DecodeError, jwt.ExpiredSignature): pass
            else:
                if token['aud'] == aud and token['iss'] == iss:
                    self.token = token
                    return True
            return False

    def get_certs(self):
        return AsyncHTTPClient().fetch(GoogleIdToken._GOOGLE_CERTS_URI)

    def _get_pubkey(self, pem):
        der = PEM_cert_to_DER_cert(pem)
        cert = DerSequence()
        cert.decode(der)
        tbs_cert = DerSequence()
        tbs_cert.decode(cert[0])  # TBSCertiFicate
        pubkey_info = tbs_cert[6]  # SubjectPublicKeyInfo
        return RSA.importKey(pubkey_info)
