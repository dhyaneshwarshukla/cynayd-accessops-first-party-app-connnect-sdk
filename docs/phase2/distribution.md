# Versioned private SDK distribution

Use a restricted npm package under the organization's approved `@cynayd` scope. This repo now contains a restricted npmjs.org release workflow and a contract workflow. The Git remote still has v0.1.1 as the last verified release and no v0.2.0 tag. No registry publish or Git push has been performed for this proposal.

## Registry setup and release

1. Confirm the company controls the npm organization `cynayd`, that its plan supports restricted packages and that the security owner authorizes the code to be published there. Grant read access to the application build teams. Grant write access only to release maintainers. The registry's access controls protect the package outside Git.
2. Protect the GitHub release tags and configure the `private-sdk-registry` environment with required reviewers and the dedicated `SDK_REGISTRY_PUBLISH_TOKEN` secret. For the initial release, use the approved granular write credential scoped to the organization/package, preferably with a short expiration. Rotate or replace it with the approved trusted publishing setup when account policy permits. Consumers use their own separate read-only credentials. Configure private vulnerability reporting or the existing organization security channel.
3. Review source, changelog, package allowlist and tests. Create the protected tag matching the stable `package.json` version and dispatch the release workflow on that tag. The validation job performs a clean install, contract tests, fixture run, staged packaging and a clean tarball install. The approval-gated job publishes **restricted** to the pinned registry, verifies SHA-256 before upload, and checks the registry's `dist.integrity` against the tested package. The artifacts contain the exact tarball, SHA-256 and npm integrity. Publish the changelog and digests in the matching private release record.
4. The tracked project stays `private: true` to guard accidental publishing. The release pack script removes that flag only in a temporary copy and adds restricted npmjs.org publishing metadata. The local v0.2.0 preview tarball used a different manifest and is not the registry release integrity reference.

For developer and CI installs, use the following configuration and store tokens in the approved secret store. Public dependencies continue to resolve through the normal registry.

```ini
@cynayd:registry=https://registry.npmjs.org/
//registry.npmjs.org/:_authToken=${NPM_TOKEN}
```

```sh
npm install --save-exact @cynayd/accessops-first-party-app-connnect-sdk@0.2.0
npm view @cynayd/accessops-first-party-app-connnect-sdk@0.2.0 dist.integrity
```

Install at the owning workspace package, keep the existing package manager, and commit its exact dependency and lockfile. Use the equivalent exact-version pnpm command where applicable. Verify the lockfile integrity matches the private release record. Do not silently upgrade via a range or pull from a floating branch. Existing Git consumers can retain their current full-commit dependency until the restricted release is published and their application acceptance is complete.

## Compatibility and updates

| Release or environment | Compatibility |
| --- | --- |
| v0.1.1 consumers | Existing Ed25519 product authorization API. Continue the known pin until qualified. |
| v0.2.0 | Adds One delegation contract v1. Existing API exports remain. CI fixture matrix covers Node 22 and 24; source manifest maintains the prior minimum engine. |
| One Identity | Connect requires launch provenance, live canonical AccessOps decisions and the existing registered delegation endpoints. |
| Drive, Docs and Grid | Keep existing paths until authenticated target acceptance. Update shared transport imports per application and rerun read and write compatibility. |
| Calendar | Separate registration and qualification workstream. |

The contract workflow runs typecheck, SDK protocol and compatibility tests, and the authenticated mock fixture on every change. One's isolated database suite remains the authority-side acceptance check. Maintainers follow [SECURITY.md](../../SECURITY.md) to issue advisories and notify each consuming repo of patched versions. [AGENTS.md](../../AGENTS.md) describes consumer pinning and qualification expectations.
