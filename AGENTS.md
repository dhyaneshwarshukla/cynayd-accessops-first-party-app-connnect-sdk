# CYNAYD first-party authentication SDK

- Use the installed package and the [versioned contract](docs/contract-v1.md) for interactive access. Obtain user provenance from One and preserve canonical AccessOps decisions and resource ACLs.
- Treat registered application keys, resource audiences, installation IDs and scopes as operator-supplied values. Report missing registrations or grants before rollout.
- Keep One user credentials, assertion keys and DPoP keys on the responsible backend. Use an atomic session revision check on reconnect and an atomic shared replay store at the resource.
- Keep the SDK independent of database, secret-vault and HTTP framework implementations. Preserve the v0.1.1 AccessOps exports and transport behavior.
- The checked-in One profile and resource verifier are synchronized upstream modules. Check provenance before changing either. Coordinate protocol fixes in One and update both through a reviewed release.
- Run `npm run typecheck`, `npm test` and `npm run example` before handoff. The fixtures under `examples/` are test services. Production rollout requires authenticated acceptance and explicit operator change control.

For cross-repository installs, use the exact approved restricted registry version and commit the consumer lockfile. Follow [the release workflow](docs/phase2/distribution.md) and verify its integrity against the private release record. Environment owners must approve exact application and installation registrations. Use [the Connect staging gate](docs/phase2/connect-agent.md) to qualify the intended target operation before rollout.
