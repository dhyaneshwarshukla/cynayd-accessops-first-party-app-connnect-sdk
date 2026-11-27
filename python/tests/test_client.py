from datetime import datetime, timedelta, timezone
from hashlib import sha256
from time import time
import unittest
from urllib.parse import parse_qs

from cryptography.hazmat.primitives.asymmetric import ec, rsa
import httpx
import jwt

from cynayd_first_party.client import AuthorityError, DelegationClient
from cynayd_first_party.signer import DelegationSigner, _base64url
from cynayd_first_party.subject import SubjectIdentity, verify_subject
from test_signer import pem


class ClientTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.issuer = "https://one.example/"
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        proof_key = ec.generate_private_key(ec.SECP256R1())
        self.signer = DelegationSigner("client", "kid", pem(self.key), pem(proof_key))
        self.identity = SubjectIdentity("user", "org", "installation", "session", 2, int(time()) + 60)

    def test_subject_pins_exact_audience_and_session_reference(self):
        now = int(time())
        claims = {
            "iss": self.issuer, "aud": "fixture", "appSlug": "fixture", "id": "user",
            "sub": "user", "organizationId": "org", "installedAppId": "installation",
            "type": "one_delegation_subject", "launchAccessEpoch": 2, "launchJti": "reference",
            "iat": now, "exp": now + 60, "sessionBinding": {
                "sessionId": "session", "reference": "reference", "originalIat": now, "expiresAt": now + 60,
            },
        }

        def verify(payload):
            token = jwt.encode(payload, self.key, algorithm="RS256", headers={"kid": "one"})
            return verify_subject(token, issuer=self.issuer, app_slug="fixture",
                                  signing_key=lambda kid: self.key.public_key() if kid == "one" else None)

        self.assertEqual(verify(claims).installation_id, "installation")
        for bad_claims in ({"aud": ["fixture"]}, {"launchJti": "different"}, {"launchAccessEpoch": True}):
            with self.subTest(bad_claims=bad_claims), self.assertRaises(ValueError):
                verify({**claims, **bad_claims})

    async def test_launch_and_renewal_match_confidential_wire_profile(self):
        seen = []

        def handle(request):
            form = {key: values[0] for key, values in parse_qs(request.content.decode()).items()}
            assertion = jwt.decode(form["client_assertion"], self.key.public_key(), algorithms=["RS256"],
                                   audience=str(request.url))
            self.assertEqual(assertion["cnf"]["jkt"], self.signer.thumbprint)
            self.assertIn("DPoP", request.headers)
            seen.append(form)
            endpoint = request.url.path.rsplit("/", 1)[1]
            if endpoint == "bound-launch-initiate":
                return httpx.Response(200, json={"request": "r" * 43, "expires_in": 120})
            if endpoint == "bound-launch-redeem":
                self.assertEqual(form["renewal"], "optional")
                self.assertEqual(_base64url(sha256(form["verifier"].encode()).digest()), seen[0]["challenge"])
                return httpx.Response(200, json={
                    "subject_token": "signed", "renewal_status": "eligible", "renewal_generation": 1,
                    "renewal_capability": "a" * 43, "renewal_expires_at": int(time()) + 60,
                })
            self.assertEqual((form["capability"], form["generation"]), ("a" * 43, "1"))
            return httpx.Response(200, json={
                "subject_token": "new-signed", "renewal_generation": 2,
                "renewal_capability": "b" * 43, "renewal_expires_at": int(time()) + 60,
            })

        async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
            client = DelegationClient(self.issuer + "delegation/token", self.signer, http)
            launch = await client.initiate("https://workspace.example/callback")
            with self.assertRaises(AuthorityError):
                await client.redeem(launch, request=launch.request, code="c" * 43, state="s" * 43)
            result = await client.redeem(launch, request=launch.request, code="c" * 43, state=launch.state)
            self.assertEqual((await client.renew(result.capability)).capability.generation, 2)
        self.assertEqual(len(seen), 3)

    async def test_live_status_and_screen_activity_check_authority_response(self):
        future = (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()

        def handle(request):
            if request.url.path.endswith("session-status"):
                return httpx.Response(200, json={
                    "state": "ACTIVE", "reason": "SESSION_VALID", "nextAction": "NONE",
                    "accessEpoch": 2, "revision": "revision", "centralExpiresAt": future,
                    "subjectExpiresAt": future, "lastActivityAt": None, "idleExpiresAt": None,
                })
            return httpx.Response(200, json={
                "accepted": True, "updated": True, "authenticationIdleUpdated": True,
            })

        async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
            client = DelegationClient(self.issuer + "delegation/token", self.signer, http)
            self.assertEqual((await client.status("signed", self.identity))["revision"], "revision")
            with self.assertRaisesRegex(AuthorityError, "UPSTREAM_PROFILE_MISMATCH"):
                await client.report_screen("signed", self.identity, "screen.view", "i" * 16)
            with self.assertRaises(ValueError):
                await client.report_business("signed", self.identity, "screen.view", "i" * 16)
