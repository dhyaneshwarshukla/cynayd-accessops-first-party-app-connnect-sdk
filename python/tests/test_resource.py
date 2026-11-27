import unittest
from time import time
from unittest.mock import AsyncMock
from urllib.parse import parse_qs

from cryptography.hazmat.primitives.asymmetric import ec, rsa
import httpx
import jwt

from cynayd_first_party.client import AuthorityError, DelegationClient, RegisteredOperation
from cynayd_first_party.resource import DelegatedResource, ResourceIdentity
from cynayd_first_party.signer import DelegationSigner, _digest
from cynayd_first_party.subject import SubjectIdentity
from test_signer import pem


class ResourceTest(unittest.IsolatedAsyncioTestCase):
    async def test_full_delegation_keeps_scope_identity_and_live_target_acl(self):
        issuer, target = "https://one.example/", "https://drive.example"
        resource_url = target + "/files/item?revision=2"
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        signer = DelegationSigner("source-client", "key", pem(key), pem(ec.generate_private_key(ec.SECP256R1())))
        now = int(time())
        claims = {
            "iss": issuer, "aud": "drive", "sub": "person", "iat": now, "nbf": now, "exp": now + 120,
            "organization_id": "tenant", "client_id": "source-client", "azp": "source",
            "act": {"sub": "source-client"}, "type": "one_delegated_access", "mode": "DELEGATED",
            "source_installation_id": "source", "target_installation_id": "target",
            "source_epoch": 2, "target_epoch": 3, "grant_revision": 4, "client_revision": 5,
            "jti": "token-id", "scope": "drive:read", "cnf": {"jkt": signer.thumbprint},
        }
        token = jwt.encode(claims, key, algorithm="RS256", headers={"typ": "at+jwt", "kid": "key"})
        introspection = AsyncMock()
        introspection.introspect.return_value = {**claims, "active": True}
        acl = AsyncMock(return_value=True)
        replay = AsyncMock()
        replay.consume.side_effect = [True, False, True]
        resource = DelegatedResource(issuer=issuer, audience="drive", public_origin=target,
                                     signing_key=lambda _: key.public_key(), delegation=introspection,
                                     replay=replay, authorize=acl)
        proof = {}

        async def handle(request):
            if request.url.host == "one.example":
                fields = parse_qs(request.content.decode())
                self.assertEqual(fields["scope"], ["drive:read"])
                self.assertEqual(fields["subject_token"], ["source-subject"])
                return httpx.Response(200, json={
                    "access_token": token, "token_type": "DPoP", "expires_in": 120, "scope": "drive:read",
                    "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                })
            self.assertNotIn("Cookie", request.headers)
            self.assertNotIn("X-Forwarded-Host", request.headers)
            proof.update(authorization=request.headers["Authorization"], proof=request.headers["DPoP"],
                         method=request.method, path="/files/item?revision=2", required_scope="drive:read",
                         context="fixture-file")
            self.assertEqual(jwt.decode(proof["proof"], options={"verify_signature": False})["ath"], _digest(token))
            verified = await resource.authorize(**proof)
            self.assertEqual(verified, ResourceIdentity("person", "tenant", "target"))
            return httpx.Response(200, json={"saved": False})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as network:
            client = DelegationClient(issuer + "delegations/token", signer, network)
            operation = RegisteredOperation("drive", ("drive:read",), "GET", target,
                                            lambda url: str(url) == resource_url)
            identity = SubjectIdentity("person", "tenant", "source", "central", 2, now + 120)
            response = await client.call("source-subject", identity, operation, resource_url,
                                         headers={"Cookie": "none", "X-Forwarded-Host": "none"})
            self.assertEqual(response.status_code, 200)
            acl.assert_awaited_once()
            with self.assertRaisesRegex(AuthorityError, "invalid_dpop_proof"):
                await resource.authorize(**proof)
            introspection.introspect.return_value = {"active": False}
            with self.assertRaisesRegex(AuthorityError, "invalid_token"):
                await resource.authorize(**{**proof, "proof": signer.proof("GET", resource_url, token)})
            self.assertEqual(introspection.introspect.await_count, 2)
            acl.assert_awaited_once()
