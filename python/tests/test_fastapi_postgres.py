"""ASGI lifecycle and real PostgreSQL CAS. Run only with a disposable test database."""

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from secrets import token_bytes
from time import time
from urllib.parse import parse_qs, urlencode

import httpx
import jwt
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("psycopg_pool")
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi import FastAPI
from psycopg_pool import AsyncConnectionPool

from cynayd_first_party.client import Capability, DelegationClient
from cynayd_first_party.fastapi import FastAPIHost
from cynayd_first_party.postgres import PostgresHostStore
from cynayd_first_party.session import Credentials, OneApplicationSession
from cynayd_first_party.signer import DelegationSigner
from cynayd_first_party.subject import SubjectIdentity
from test_signer import pem


def test_fastapi_host_and_postgres():
    url = os.getenv("SDK_TEST_DATABASE_URL")
    if not url:
        pytest.skip("Isolated PostgreSQL test database unavailable")
    asyncio.run(qualify(url))


async def qualify(url):
    issuer, app_origin = "https://one.example/", "https://app.example"
    base = "/api/auth/one"
    secret = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer = DelegationSigner("fixture", "fixture", pem(secret), pem(ec.generate_private_key(ec.SECP256R1())))
    now = int(time())
    identity = SubjectIdentity("person", "org", "install", "central", 2, now + 120)
    subject = jwt.encode({
        "iss": issuer, "aud": "fixture", "appSlug": "fixture", "id": "person", "sub": "person",
        "organizationId": "org", "installedAppId": "install", "type": "one_delegation_subject",
        "launchAccessEpoch": 2, "launchJti": "reference", "iat": now, "exp": now + 120,
        "sessionBinding": {"sessionId": "central", "reference": "reference", "originalIat": now, "expiresAt": now + 120},
    }, secret, algorithm="RS256", headers={"kid": "fixture"})
    future = (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat()
    transactions = []
    locked = False

    def one(request):
        operation = request.url.path.rsplit("/", 1)[-1]
        fields = parse_qs(request.content.decode())
        if operation == "bound-launch-initiate":
            transactions.append(fields["state"][0])
            return httpx.Response(200, json={"request": "r" * 43, "expires_in": 120})
        if operation == "bound-launch-redeem":
            assert "renewal" not in fields
            return httpx.Response(200, json={"subject_token": subject})
        if locked:
            return httpx.Response(403, json={"code": "session_locked"})
        return httpx.Response(200, json={
            "state": "ACTIVE", "reason": "SESSION_VALID", "nextAction": "NONE", "accessEpoch": 2,
            "revision": "revision", "centralExpiresAt": future, "subjectExpiresAt": future,
            "lastActivityAt": None, "idleExpiresAt": None,
        })

    async with AsyncConnectionPool(url, min_size=1, max_size=1, open=False) as pool:
        sql = (Path(__file__).resolve().parents[2] / "examples/host/schema.sql").read_text()
        async with pool.connection() as connection:
            await connection.execute(sql.replace("CREATE TABLE", "CREATE TEMP TABLE"))
        store = PostgresHostStore(pool, token_bytes(32))
        transport = httpx.MockTransport(one)
        async with httpx.AsyncClient(transport=transport) as authority:
            client = DelegationClient(issuer + "api/v1/delegations/token", signer, authority)
            session = OneApplicationSession(client, issuer=issuer, app_slug="fixture",
                                            signing_key=lambda _: secret.public_key())
            host = FastAPIHost(app_origin=app_origin, portal_origin=issuer.rstrip("/"), base_path=base,
                               callback=app_origin + base + "/callback", cookie_label="fixture", session=session,
                               store=store, installation_for_tenant={"org": "install"}.get,
                               allows_return=lambda url: url.path == "/")
            app = FastAPI()
            app.include_router(host.router)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=app_origin) as browser:
                assert (await browser.post(base + "/start", json={})).status_code == 403
                headers = {"Origin": app_origin}

                async def begin():
                    response = await browser.post(base + "/start", json={"returnTo": "//external.example"}, headers=headers)
                    assert response.status_code == 200
                    assert response.json()["authorizationUrl"].startswith(issuer + "apps/bound-launch?")
                    assert "HttpOnly" in response.headers["Set-Cookie"]
                    query = urlencode({"request": "r" * 43, "code": "c" * 43, "state": transactions[-1]})
                    return base + "/callback?" + query

                callback = await begin()
                finished = await browser.get(callback)
                assert finished.status_code == 303 and finished.headers["location"] == app_origin + "/"
                assert (await browser.get(callback)).status_code == 401
                token = browser.cookies[host.session_cookie]
                assert (await browser.get(base + "/session")).json()["userId"] == "person"
                locked = True
                assert (await browser.get(base + "/session")).json()["nextAction"] == "UNLOCK"
                assert len((await browser.post(base + "/unlock-binding", headers=headers)).json()["binding"]) == 43
                locked = False
                refreshed = await browser.get(await begin())
                assert refreshed.status_code == 303
                assert await store.read(token) is None
                current = browser.cookies[host.session_cookie]
                assert (await browser.post(base + "/logout", headers=headers)).status_code == 204
                assert await store.read(current) is None

        await store.create_launch("claim", {"request": "request", "state": "state", "prior_id": None}, 120)
        claim, replay = await asyncio.gather(*[
            store.consume_launch("claim", request="request", state="state", prior_id=None) for _ in range(2)
        ])
        winner = claim or replay
        assert bool(claim) != bool(replay)
        old = Credentials(identity, subject, Capability("a" * 43, 1, now + 140))
        assert await store.activate("claim", winner[0], old, None)
        revision, _ = await store.read("claim")
        disposition, claimed = await store.claim("claim", revision, 1)
        assert disposition == "claimed"
        assert (await store.claim("claim", claimed, 1))[0] == "in_progress"
        assert not await store.replace("claim", revision, old)
        assert await store.replace("claim", claimed, old)
