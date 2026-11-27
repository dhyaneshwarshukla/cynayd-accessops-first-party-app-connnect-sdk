"""Run behind the application's existing HTTPS reverse proxy with uvicorn."""

from contextlib import asynccontextmanager
from base64 import urlsafe_b64decode
import json
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import httpx
from psycopg_pool import AsyncConnectionPool

from cynayd_first_party.client import AuthorityError, DelegationClient
from cynayd_first_party.fastapi import FastAPIHost, HostError, host_error_response
from cynayd_first_party.jwks import one_signing_keys
from cynayd_first_party.postgres import PostgresHostStore
from cynayd_first_party.session import OneApplicationSession
from cynayd_first_party.signer import DelegationSigner

env = os.environ
pool = AsyncConnectionPool(env["HOST_DATABASE_URL"], open=False)
authority = httpx.AsyncClient(trust_env=False)
issuer = env["ONE_ISSUER"]
signer = DelegationSigner(env["ONE_CLIENT_ID"], env["ONE_ASSERTION_KID"],
                          Path(env["ONE_ASSERTION_KEY_FILE"]).read_bytes(), Path(env["ONE_PROOF_KEY_FILE"]).read_bytes())
client = DelegationClient(env["ONE_TOKEN_ENDPOINT"], signer, authority)
session = OneApplicationSession(client, issuer=issuer, app_slug=env["ONE_APP_SLUG"],
                                signing_key=one_signing_keys(env["ONE_JWKS_URL"], issuer, authority))
seal_key = urlsafe_b64decode(env["HOST_SEAL_KEY"] + "=")
installations = json.loads(env["ONE_APPROVED_INSTALLATIONS"])
store = PostgresHostStore(pool, seal_key)
host = FastAPIHost(app_origin=env["APP_ORIGIN"], portal_origin=env["ONE_PORTAL_ORIGIN"], base_path="/api/auth/one",
                   callback=env["ONE_EXACT_CALLBACK"], cookie_label=env["ONE_COOKIE_LABEL"],
                   session=session, store=store, installation_for_tenant=installations.get,
                   allows_return=lambda url: url.path == "/" and not url.query,
                   renewal=env.get("ONE_APPROVED_RENEWAL") == "true")


@asynccontextmanager
async def lifespan(_app):
    async with pool, authority:
        yield


app = FastAPI(lifespan=lifespan)
app.include_router(host.router)


@app.get("/api/me")
async def me(request: Request):
    try:
        credentials, _ = await host.authenticate(request)
        identity = credentials.identity
        return JSONResponse({"userId": identity.user_id, "tenantId": identity.tenant_id,
                             "installedAppId": identity.installation_id}, headers={"Cache-Control": "no-store"})
    except (AuthorityError, HostError) as error:
        return host_error_response(error)
