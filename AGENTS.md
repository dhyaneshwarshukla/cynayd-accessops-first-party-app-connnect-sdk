# CYNAYD first-party authentication SDK

- Use the installed package and the [versioned contract](docs/contract-v1.md) for interactive access. Obtain user provenance from One and preserve canonical AccessOps decisions and resource ACLs.
- Treat registered application keys, resource audiences, installation IDs and scopes as operator-supplied values. Report missing registrations or grants before rollout.
- Keep One user credentials, assertion keys and DPoP keys on the responsible backend. Use an atomic session revision check on reconnect and an atomic shared replay store at the resource.
- Keep the SDK independent of database, secret-vault and HTTP framework implementations. Preserve the v0.1.1 AccessOps exports and transport behavior.
- The checked-in One profile and resource verifier are synchronized upstream modules. Check provenance before changing either. Coordinate protocol fixes in One and update both through a reviewed release.
- Run `npm run typecheck`, `npm test` and `npm run example` before handoff. The fixtures under `examples/` are test services. Production rollout requires authenticated acceptance and explicit operator change control.

For cross-repository installs, use the exact approved restricted registry version and commit the consumer lockfile. Follow [the release workflow](docs/phase2/distribution.md) and verify its integrity against the private release record. Environment owners must approve exact application and installation registrations. Use [the Connect staging gate](docs/phase2/connect-agent.md) to qualify the intended target operation before rollout.

Use the [session renewal contract](docs/session-renewal-v1.md) for v0.3.0 integrations. Bind callbacks to the initiating application session, advance credentials with atomic revision checks, and keep autosave and polling independent of central activity.

Use the [unified session contract](docs/unified-session-v1.md) for passive status and lock integration. Keep central validation in the backend and treat browser invalidation as an advisory signal to recheck.

Use the [v0.5.0 activity, lock and relay contract](docs/unified-session-v2.md). Keep activity adapters behind authorized interactive product commands and require live checks for protected operations.

Use the [v0.6 candidate contract](docs/unified-session-v3.md) for qualified
authentication activity. Product adapters must report an accepted authorized
business command, never a browser heartbeat or autosave. Backend source
renewal requires a reviewed One protocol. Keep verified browser resume until
that protocol is implemented and qualified.

Use the [bound launch contract](docs/bound-launch-v1.md) only for staging
qualification. Keep the verifier and returned subject on the server.
Verify host transaction state and credentials before committing a session.
A bound launch does not provide a silent renewal capability.
