from dataclasses import replace
from time import time
import unittest
from unittest.mock import AsyncMock

from cynayd_first_party.client import AuthorityError, Capability
from cynayd_first_party.session import Credentials, OneApplicationSession
from cynayd_first_party.subject import SubjectIdentity


class SessionTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        now = int(time())
        self.identity = SubjectIdentity("user", "tenant", "install", "central", 2, now + 15)
        self.current = Credentials(self.identity, "old", Capability("a" * 43, 1, now + 100))
        self.client = AsyncMock()
        self.sdk = OneApplicationSession(self.client, issuer="https://one.example",
                                        app_slug="fixture", signing_key=lambda _: None)
        self.store = AsyncMock()
        self.store.read.return_value = ("original", self.current)
        self.store.claim.return_value = ("claimed", "claim")
        self.store.replace.return_value = True

    async def test_locked_unspent_restores_only_the_claimed_revision(self):
        self.client.renew.side_effect = AuthorityError(403, "source_renewal_locked_unspent", "id", "UNLOCK")
        with self.assertRaises(AuthorityError) as result:
            await self.sdk.active("host", self.store)
        self.assertEqual(result.exception.action, "UNLOCK")
        self.store.replace.assert_awaited_once_with("host", "claim", self.current)
        self.client.status.assert_not_called()

    async def test_ambiguous_dispatch_leaves_claim_for_browser_recovery(self):
        self.client.renew.side_effect = AuthorityError(503, "UPSTREAM_UNAVAILABLE", "id", "RETRY")
        with self.assertRaises(AuthorityError) as result:
            await self.sdk.active("host", self.store)
        self.assertEqual(result.exception.action, "REAUTHENTICATE")
        self.store.replace.assert_not_called()
        self.store.claim.return_value = ("recovery_required", None)
        with self.assertRaisesRegex(AuthorityError, "SOURCE_RENEWAL_UNKNOWN"):
            await self.sdk.active("host", self.store)
        self.client.renew.assert_awaited_once()

    async def test_ineligible_source_still_allows_an_active_session(self):
        ineligible = replace(self.current, capability=None)
        self.store.read.return_value = ("original", ineligible)
        self.client.status.return_value = {"state": "ACTIVE"}
        self.assertEqual(await self.sdk.active("host", self.store), (ineligible, {"state": "ACTIVE"}))
        self.store.claim.assert_not_called()
        self.client.renew.assert_not_called()
