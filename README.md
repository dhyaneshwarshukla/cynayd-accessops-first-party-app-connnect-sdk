# CYNAYD AccessOps First-Party App Connection SDK

The shared first-party integration for One confidential bound launch, verified host sessions, central Smart Lock, and application-to-application delegation. Use the backend for live One and AccessOps decisions and the browser entry point for same-origin status, recovery, and unlock.

- [Canonical onboarding guide](docs/onboarding.md)
- [One registration and operator tooling](docs/registration.md)
- [Delegated operation examples and availability](docs/delegated-operations.md)
- [Versioned host contract](docs/common-integration-v1.md)
- [Gap closure and release evidence](docs/gap-closure-rc9.md)
- [Legacy product evaluation compatibility](docs/legacy-product-evaluate.md)

## Local verification

```sh
npm ci
npm run typecheck
npm test
npm run example
```

With Express and pg installed in the reference app, run `node examples/host/qualify.cjs` with `SDK_TEST_DATABASE_URL` set to a disposable PostgreSQL database. For Python install `./python[fastapi]` and pytest, then run `python -m pytest python/tests` with the same test configuration. The standalone fixtures issue their own test credentials and never contact One or a target application.
