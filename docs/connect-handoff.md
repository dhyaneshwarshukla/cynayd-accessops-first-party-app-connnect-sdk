# Connect migration and production compatibility

## Registry and endpoints checked on 2026-11-25 UTC

The running One backend advertises the public `auth.one.cynayd.com` delegation endpoint. Read-only registry checks used its configured database. A registered public KID establishes a currently valid public credential record. It does not prove private key possession or target verifier deployment.

| Item | Drive | Calendar |
| --- | --- | --- |
| Canonical application | Active `cynayd-drive`, One app ID `cmfcyq27n0000shwweuuq8cf6` | Active `cynayd-calendar-tasks`, ID `cmje60yob00apqf0iaakmypcv`. `cynayd-calender-local` is a separate active app, ID `cmk3u0aon0xg3li0ii07xfat8`. Confirm the production integration targets the Calendar/Tasks app. |
| Installation resolution | Four current Drive installations. Four tenants have both canonical Connect and Drive installations. | Six current Calendar/Tasks installations. Four tenants have both canonical Connect and Calendar/Tasks installations. |
| Target registration | Active `cynayd-drive` audience, with `drive:read` and `drive:write`. Active `cynayd-drive-resource` client with valid KID `cynayd-drive-rsa-20261027-82c4a06e1d` and configured `drive:read` client scope. | No Calendar-family resource audience, client, valid key or registered operation scope. Older `cynayd-calendar` and `cynayd-calender` catalog entries are not the observed installed key. |
| Connect source and grants | Active `cynayd-connect`, ID `cmffr7in2000v10clilb52asx`, with four current installations. No delegation client, valid key or active grant for Connect. | Same source blocker. Calendar additionally needs a verified target registration and exact scope mapping. |
| Other grants | Docs and Grid each had an active tenant delegation grant to Drive with `drive:read` and `drive:write`. They do not authorize Connect. | No registered Calendar resource grants. |
| Target endpoints | Prior handoff supplies the verifier. Registry presence does not establish deployed DPoP handling, live introspection or ACL enforcement for Connect attachment routes. Verify operation routes with a properly authorized test client. | Local Calendar source search found no DPoP or delegation introspection integration. Deployed route acceptance and resource ACL enforcement remain unverified. |

Scope spelling is exact and case sensitive. Confirm the target's route-to-scope mapping before configuration. In particular, Drive resource write scope being available does not establish that folder-creation and upload routes actually verify it. Keep the Calendar audience and operation scope values unset until its owner and registrar confirm them.

## Engineering handoff

1. **Connect login and reconnect.** Inventory Connect's deployed callback and session middleware. Map its verified local user and tenant to the canonical One person, org and source installation. Integrate the registered One return, then use `OneApplicationSession` to acquire and securely store the verified subject. Coordinate callback state or a verified direct launch with the One portal team. One does not echo an arbitrary state parameter supplied to its redemption endpoint.
2. **Backend delegation.** Instantiate a single configured `DelegationClient` for Connect. Remove attribute-only minting from the new interactive path for Drive and Calendar. Call `delegation.call` with fixed operation descriptions resolved from the approved registrations. Attach only the narrowest scope for each Drive list/read/create/upload or Calendar read/create/update operation.
3. **Chat callers.** Change the frontend and any separate Chat service from a token-fetch flow to authenticated Connect backend operations. Route through whichever backend holds the proof key. Verify chat membership, attachment permissions and file size/type constraints at the operation boundary. Prove that the eventual Drive call still runs with the authenticated user's identity. Retire `/api/v1/integrations/drive/token` for migrated callers once compatibility is verified.
4. **Target middleware.** Verify or mount `DelegatedResource` in Drive and Calendar only on the intended routes. Use target-specific introspection credentials and durable shared replay state. Use verified person, organization and installation in local tenant lookup and resource ACL checks. Confirm that a centrally valid token cannot operate on an unauthorized folder or event.
5. **Error translation.** Remove blanket 500 mapping from the interactive path. Return the specific failure status, structured reason and request ID. Render a reconnect action for expired or missing source evidence. Keep authority unavailability, rate limits, configuration blockers and resource denials distinct. If an upload or event write could have completed, check its outcome before retry or use the target's idempotency facility.
6. **Feature-by-feature transition.** Qualify Drive read and writes and Calendar read and writes using approved test registrations and unchanged production access policy. Immediately keep legacy noninteractive and unrelated login paths intact. Reconnect legacy interactive sessions through One when the migrated feature requires evidence. Roll back a failing integration by disabling the new interactive path rather than restoring attribute minting.
7. **Acceptance evidence.** Capture sanitized Connect request ID, initiation mode, selected server-side operation, One exchange status and target status. Confirm canonical person/org/installation, verify logout and grant/key revocation in staging, and run denied and cross-tenant cases. Use the [local example](../examples/connect.cjs) for wiring and the [qualification plan](qualification.md) for evidence.

## Application impact and compatibility matrix

| Caller | Target | Transition |
| --- | --- | --- |
| Connect and Chat | Drive, Calendar | Immediate migration. Both require Connect registration and authorized grants. Calendar also needs target implementation and resource registration. |
| Docs | Drive | Existing implementation reference and active registry records. Qualify authenticated lifecycle and switch the client to the shared SDK after acceptance. |
| Grid (`cynayd-sheets`) | Drive | Existing client implementation and active registry records. Migrate the duplicated client only after behavior parity verification. |
| Mail | Drive, Docs, Grid | Inventory per-user operations and registered launch. Only Drive was seen as a delegation resource in this registry. Validate equivalent target support before enabling. |
| Drive | Docs, Grid | Use One-backed Drive session and the same client. Target registration and capability review required. |
| Groot | Authorized first-party targets | Bind interactive tool execution to the current canonical user and tenant. Qualify each target operation and scope separately. |
| Calendar and HR | Existing attribute-based login/API paths | Local source references the legacy endpoint. Inventory callers and migrate any affected interactive path to verified provenance. |
| Vault | One SAML continuation | Keep verified SAML redemption and run the existing regression. |
| Other and future apps | Any approved first-party resource | Follow the shared onboarding checklist and require a registered audience, client, grant, target verifier and local ACL adapter. |

The SDK package is locally qualified. **Production Connect migration is blocked.** No production client, resource, grant, runtime configuration or deployment was changed.
