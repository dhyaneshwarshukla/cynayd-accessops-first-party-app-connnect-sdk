import base64
import hashlib
import json
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
import jwt

from cynayd_first_party.signer import DelegationSigner


def pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


class DelegationSignerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.proof_key = ec.generate_private_key(ec.SECP256R1())
        cls.signer = DelegationSigner("fixture-client", "fixture-kid", pem(cls.key), pem(cls.proof_key))

    def test_assertion_and_proof_bind_the_same_public_key(self):
        endpoint = "https://one.example/api/launch"
        assertion = self.signer.assertion(endpoint)
        proof = self.signer.proof("post", endpoint + "?unused=1", "fixture-token")
        claims = jwt.decode(assertion, self.key.public_key(), algorithms=["RS256"], audience=endpoint)
        proof_claims = jwt.decode(proof, self.proof_key.public_key(), algorithms=["ES256"])
        header = jwt.get_unverified_header(proof)
        jwk_bytes = json.dumps(header["jwk"], sort_keys=True, separators=(",", ":")).encode()
        thumbprint = base64.urlsafe_b64encode(hashlib.sha256(jwk_bytes).digest()).rstrip(b"=").decode()
        self.assertEqual(claims["cnf"]["jkt"], thumbprint)
        self.assertEqual(claims["iss"], claims["sub"])
        self.assertEqual(claims["exp"] - claims["iat"], 30)
        self.assertEqual(jwt.get_unverified_header(assertion)["kid"], "fixture-kid")
        self.assertEqual(header["typ"], "dpop+jwt")
        self.assertNotIn("d", header["jwk"])
        self.assertEqual(proof_claims["htu"], endpoint)
        self.assertEqual(proof_claims["htm"], "POST")
        self.assertNotEqual(claims["jti"], proof_claims["jti"])
        token_digest = hashlib.sha256(b"fixture-token").digest()
        self.assertEqual(proof_claims["ath"], base64.urlsafe_b64encode(token_digest).rstrip(b"=").decode())

    def test_rejects_untrusted_endpoint_shapes(self):
        for endpoint in ("http://one.example", "https://key@one.example", "https://one.example/#"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                self.signer.proof("GET", endpoint)
        with self.assertRaises(ValueError):
            self.signer.assertion("https://one.example/path?value=1")
        proof = self.signer.proof("GET", "https://one.example?x=1")
        claims = jwt.decode(proof, self.proof_key.public_key(), algorithms=["ES256"])
        self.assertEqual(claims["htu"], "https://one.example/")
        self.assertNotIn("ath", claims)
